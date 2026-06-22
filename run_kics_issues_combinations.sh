#!/usr/bin/env bash
# Run 4 combinations of KICS issue positive-file pairs through run_all_descriptions.sh.
#
# Usage:
#   ./run_kics_issues_combinations.sh <model> <validation_history_iterations> [--max-runs N] [--provider P]
#
# Example:
#   ./run_kics_issues_combinations.sh eu.anthropic.claude-sonnet-4-6 -1 --max-runs 5 --provider bedrock

set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <model> <validation_history_iterations> [--max-runs N] [--provider openrouter|bedrock]"
    exit 1
fi

MODEL="$1"
VALIDATION_HISTORY_ITERATIONS="$2"
shift 2

MAX_RUNS="${MAX_RUNS:-1}"
PROVIDER="${PROVIDER:-openrouter}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --max-runs)    MAX_RUNS="$2";  shift 2 ;;
        --max-runs=*)  MAX_RUNS="${1#*=}"; shift ;;
        --provider)    PROVIDER="$2"; shift 2 ;;
        --provider=*)  PROVIDER="${1#*=}"; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXAMPLES_SOURCE="$SCRIPT_DIR/validation/examples_kics_issue"
TEMP_DIR="$SCRIPT_DIR/validation/tmp_kics_combo"
GENERATED_REGO="$SCRIPT_DIR/generated_rego"

# ---------------------------------------------------------------------------
# run_combination <experiment_name> <smell>:<yaml_file>:<tf_file> [...]
# ---------------------------------------------------------------------------
run_combination() {
    local experiment_name="$1"
    shift

    echo ""
    echo "========================================"
    echo "  Combination: $experiment_name"
    echo "========================================"

    rm -rf "$TEMP_DIR"
    mkdir -p "$TEMP_DIR"

    local smells=()

    for triplet in "$@"; do
        IFS=':' read -r smell yaml_file tf_file <<< "$triplet"
        local smell_dir="$TEMP_DIR/$smell"
        mkdir -p "$smell_dir"

        cp "$EXAMPLES_SOURCE/$smell/$yaml_file" "$smell_dir/"
        cp "$EXAMPLES_SOURCE/$smell/$tf_file"   "$smell_dir/"

        python3 "$SCRIPT_DIR/filter_manifest.py" \
            "$EXAMPLES_SOURCE/$smell/${smell}.json" \
            "$smell_dir/${smell}.json" \
            "$yaml_file" "$tf_file"

        smells+=("$smell")
    done

    ./run_all_descriptions.sh \
        "$MODEL" \
        "$experiment_name" \
        "$TEMP_DIR" \
        glitch \
        "$VALIDATION_HISTORY_ITERATIONS" \
        --max-runs "$MAX_RUNS" \
        --provider "$PROVIDER" \
        "${smells[@]}"

    rm -rf "$TEMP_DIR"
}

# ---------------------------------------------------------------------------
# Combinations
# ---------------------------------------------------------------------------
run_combination "first_combination" \
    "sec_aws_asg_no_elbs:positive1.yaml:positive1.tf" \
    "sec_aws_cmk_rotation_disabled:positive1.yaml:positive1.tf" \
    "sec_aws_cmk_unusable:positive1.yaml:positive.tf"

run_combination "second_combination" \
    "sec_aws_asg_no_elbs:positive1.yaml:positive2.tf" \
    "sec_aws_cmk_rotation_disabled:positive1.yaml:positive2.tf" \
    "sec_aws_cmk_unusable:positive2.yaml:positive.tf"

run_combination "third_combination" \
    "sec_aws_asg_no_elbs:positive2.yaml:positive1.tf" \
    "sec_aws_cmk_rotation_disabled:positive2.yaml:positive1.tf"

run_combination "fourth_combination" \
    "sec_aws_asg_no_elbs:positive2.yaml:positive2.tf" \
    "sec_aws_cmk_rotation_disabled:positive2.yaml:positive2.tf"

# ---------------------------------------------------------------------------
# Collect results
# ---------------------------------------------------------------------------
echo ""
echo "Moving results into generated_rego/kics_issue_tests/ ..."
mkdir -p "$GENERATED_REGO/kics_issue_tests"

for combo in first_combination second_combination third_combination fourth_combination; do
    if [[ -d "$GENERATED_REGO/$combo" ]]; then
        mv "$GENERATED_REGO/$combo" "$GENERATED_REGO/kics_issue_tests/"
        echo "  Moved: $combo"
    fi
done

echo ""
echo "Done."
