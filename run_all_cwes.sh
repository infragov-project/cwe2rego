#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 6 ]]; then
    echo "Usage: $0 <model> <experiment_name> <examples_dir> <analysis_tool> <validation_history_iterations> [--max-runs N] [--provider openrouter|bedrock] <cwe1> [cwe2 ...]"
    echo "Example: $0 openai/gpt-5.2-codex extension_examples_test validation/examples_extension glitch 1 --max-runs 5 --provider openrouter 284 250 319"
    exit 1
fi

MODEL="$1"
EXPERIMENT_NAME="$2"
SEMANTIC_EXAMPLES_DIR="$3"
ANALYSIS_TOOL="$4"
VALIDATION_HISTORY_ITERATIONS="$5"
shift 5

MAX_RUNS="${MAX_RUNS:-1}"
PROVIDER="${PROVIDER:-openrouter}"
EXTRA_ARGS=()

# Optional flags before CWE numbers (CWE numbers must be numeric, so this is unambiguous).
while [[ $# -gt 0 ]]; do
    case "$1" in
        --max-runs)
            if [[ $# -lt 2 ]]; then
                echo "Error: --max-runs requires a value" >&2
                exit 1
            fi
            MAX_RUNS="$2"
            shift 2
            ;;
        --max-runs=*)
            MAX_RUNS="${1#*=}"
            shift 1
            ;;
        --provider)
            if [[ $# -lt 2 ]]; then
                echo "Error: --provider requires a value" >&2
                exit 1
            fi
            PROVIDER="$2"
            shift 2
            ;;
        --provider=*)
            PROVIDER="${1#*=}"
            shift 1
            ;;
        --*)
            EXTRA_ARGS+=("$1")
            shift
            ;;
        *)
            break
            ;;
    esac
done

if ! [[ "$MAX_RUNS" =~ ^[0-9]+$ ]] || (( MAX_RUNS < 1 )); then
    echo "Error: --max-runs (or MAX_RUNS env var) must be a positive integer, got: $MAX_RUNS" >&2
    exit 1
fi

declare -A TYPE_BY_CWE=(
    [250]="sec_def_admin"
    [258]="sec_empty_pass"
    [259]="sec_hard_pass"
    [284]="sec_invalid_bind"
    [319]="sec_https"
    [326]="sec_weak_crypt"
    [327]="sec_weak_crypt"
    [353]="sec_no_int_check"
    [478]="sec_no_default_switch"
    [546]="sec_susp_comm"
    [798]="sec_hard_secr"
    [1327]="sec_invalid_bind"
)

if [[ ! -d "$SEMANTIC_EXAMPLES_DIR" ]]; then
    echo "Error: semantic examples directory not found: $SEMANTIC_EXAMPLES_DIR"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 not found in PATH"
    exit 1
fi

failed_cwes=()

for cwe in "$@"; do
    if [[ ! "$cwe" =~ ^[0-9]+$ ]]; then
        echo "Error: invalid CWE number: $cwe"
        exit 1
    fi

    TYPE_NAME="${TYPE_BY_CWE[$cwe]:-}"
    if [[ -z "$TYPE_NAME" ]]; then
        echo "Error: no type-name mapping found for CWE-$cwe"
        exit 1
    fi

    echo ""
    echo "=== Running CWE-$cwe (type: $TYPE_NAME) | max runs: $MAX_RUNS ==="

    success=0
    last_exit_code=0

    for attempt in $(seq 1 "$MAX_RUNS"); do
        echo "Attempt $attempt/$MAX_RUNS for CWE-$cwe..."

        if python3 llm_interaction.py "$MODEL" \
            --cwe "$cwe" \
            --type-name "$TYPE_NAME" \
            --experiment-name "$EXPERIMENT_NAME" \
            --semantic-examples-dir "$SEMANTIC_EXAMPLES_DIR" \
            --analysis-tool "$ANALYSIS_TOOL" \
            --validation-history-iterations "$VALIDATION_HISTORY_ITERATIONS" \
            --provider "$PROVIDER" \
            "${EXTRA_ARGS[@]}"; then
            echo "CWE-$cwe completed successfully."
            success=1
            break
        else
            last_exit_code=$?
            echo "Warning: CWE-$cwe failed on attempt $attempt (exit code: $last_exit_code)."
            if (( attempt < MAX_RUNS )); then
                echo "Retrying CWE-$cwe..."
            fi
        fi
    done

    if (( success == 0 )); then
        failed_cwes+=("$cwe:$last_exit_code")
        echo "Warning: CWE-$cwe ultimately failed after $MAX_RUNS attempts (exit code: $last_exit_code). Continuing..."
    fi
done

echo ""
if (( ${#failed_cwes[@]} > 0 )); then
    echo "Done with failures."
    echo "Failed CWEs:"
    for failure in "${failed_cwes[@]}"; do
        failed_cwe="${failure%%:*}"
        failed_exit="${failure##*:}"
        echo "  - CWE-$failed_cwe (exit code: $failed_exit)"
    done
    exit 1
fi

echo "Done."