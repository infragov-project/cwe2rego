#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 7 ]]; then
    echo "Usage: $0 <model> <type_name> <experiment_name> <examples_dir> <analysis_tool> <validation_history_iterations> <cwe1> [cwe2 ...]"
    echo "Example: $0 openai/gpt-5.2-codex sec_invalid_bind extension_examples_test validation/examples_extension glitch 1 284 250 319"
    exit 1
fi

MODEL="$1"
TYPE_NAME="$2"
EXPERIMENT_NAME="$3"
SEMANTIC_EXAMPLES_DIR="$4"
ANALYSIS_TOOL="$5"
VALIDATION_HISTORY_ITERATIONS="$6"
shift 6

if [[ ! -d "$SEMANTIC_EXAMPLES_DIR" ]]; then
    echo "Error: semantic examples directory not found: $SEMANTIC_EXAMPLES_DIR"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 not found in PATH"
    exit 1
fi

for cwe in "$@"; do
    if [[ ! "$cwe" =~ ^[0-9]+$ ]]; then
        echo "Error: invalid CWE number: $cwe"
        exit 1
    fi

    echo ""
    echo "=== Running CWE-$cwe ==="
    python3 llm_interaction.py "$MODEL" \
        --cwe "$cwe" \
        --type-name "$TYPE_NAME" \
        --experiment-name "$EXPERIMENT_NAME" \
        --semantic-examples-dir "$SEMANTIC_EXAMPLES_DIR" \
        --analysis-tool "$ANALYSIS_TOOL" \
        --use-rag \
        --validation-history-iterations "$VALIDATION_HISTORY_ITERATIONS"
done

echo ""
echo "Done."