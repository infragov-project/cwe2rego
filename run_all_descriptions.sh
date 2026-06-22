#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 5 ]]; then
    echo "Usage: $0 <model> <experiment_name> <examples_dir> <analysis_tool> <validation_history_iterations> [--max-runs N] [--provider openrouter|bedrock] <type_name1> [type_name2 ...]"
    echo "Example: $0 openai/gpt-5.2-codex my_experiment validation/examples glitch 1 --max-runs 5 --provider openrouter sec_hard_pass sec_https"
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

if [[ ! -d "$SEMANTIC_EXAMPLES_DIR" ]]; then
    echo "Error: semantic examples directory not found: $SEMANTIC_EXAMPLES_DIR"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 not found in PATH"
    exit 1
fi

failed_types=()

for type_name in "$@"; do
    echo ""
    echo "=== Running $type_name | max runs: $MAX_RUNS ==="

    success=0
    last_exit_code=0

    for attempt in $(seq 1 "$MAX_RUNS"); do
        echo "Attempt $attempt/$MAX_RUNS for $type_name..."

        if python3 llm_interaction.py "$MODEL" \
            --description \
            --type-name "$type_name" \
            --experiment-name "$EXPERIMENT_NAME" \
            --semantic-examples-dir "$SEMANTIC_EXAMPLES_DIR" \
            --analysis-tool "$ANALYSIS_TOOL" \
            --validation-history-iterations "$VALIDATION_HISTORY_ITERATIONS" \
            --provider "$PROVIDER" \
            "${EXTRA_ARGS[@]}"; then
            echo "$type_name completed successfully."
            success=1
            break
        else
            last_exit_code=$?
            echo "Warning: $type_name failed on attempt $attempt (exit code: $last_exit_code)."
            if (( attempt < MAX_RUNS )); then
                echo "Retrying $type_name..."
            fi
        fi
    done

    if (( success == 0 )); then
        failed_types+=("$type_name:$last_exit_code")
        echo "Warning: $type_name ultimately failed after $MAX_RUNS attempts (exit code: $last_exit_code). Continuing..."
    fi
done

echo ""
if (( ${#failed_types[@]} > 0 )); then
    echo "Done with failures."
    echo "Failed types:"
    for failure in "${failed_types[@]}"; do
        failed_type="${failure%%:*}"
        failed_exit="${failure##*:}"
        echo "  - $failed_type (exit code: $failed_exit)"
    done
    exit 1
fi

echo "Done."
