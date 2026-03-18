#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 6 ]]; then
    echo "Usage: $0 <model> <experiment_name> <examples_dir> <analysis_tool> <validation_history_iterations> <cwe1> [cwe2 ...]"
    echo "Example: $0 openai/gpt-5.2-codex extension_examples_test validation/examples_extension glitch 1 284 250 319"
    exit 1
fi

MODEL="$1"
EXPERIMENT_NAME="$2"
SEMANTIC_EXAMPLES_DIR="$3"
ANALYSIS_TOOL="$4"
VALIDATION_HISTORY_ITERATIONS="$5"
shift 5

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
    echo "=== Running CWE-$cwe (type: $TYPE_NAME) ==="
    if python3 llm_interaction.py "$MODEL" \
        --cwe "$cwe" \
        --type-name "$TYPE_NAME" \
        --experiment-name "$EXPERIMENT_NAME" \
        --semantic-examples-dir "$SEMANTIC_EXAMPLES_DIR" \
        --analysis-tool "$ANALYSIS_TOOL" \
        --use-rag \
        --validation-history-iterations "$VALIDATION_HISTORY_ITERATIONS"; then
        echo "CWE-$cwe completed successfully."
    else
        exit_code=$?
        failed_cwes+=("$cwe:$exit_code")
        echo "Warning: CWE-$cwe failed (exit code: $exit_code). Continuing..."
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