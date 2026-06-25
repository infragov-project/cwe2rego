# RegoSmith

LLM pipeline that generates Rego security rules for the [GLITCH](https://github.com/sr-lab/GLITCH) and KICS IaC analysis frameworks.
Rules can be generated from a CWE description or from a plain natural language description of the security smell to detect.

---

## Installation

### Dependencies

```bash
python -m pip install -r requirements.txt
```

### Environment variables

Create a `.env` file in the project root. Which variables are required depends on the provider:

**OpenRouter** (default):
```
OPENROUTER_API_KEY=your-openrouter-key
```

**Amazon Bedrock**:
```
AWS_BEARER_TOKEN_BEDROCK=your-bedrock-api-key
AWS_DEFAULT_REGION=your-region
```

### GLITCH

The pipeline installs GLITCH automatically on first run (`validation/GLITCH/`). To install manually:

```bash
mkdir -p validation/GLITCH && git clone https://github.com/sr-lab/GLITCH.git validation/GLITCH
```

Followed by downloading the necessary binary for your system, available [here](https://github.com/sr-lab/GLITCH/releases/tag/rego_python-v0.2.0).
After downloading, place it in the following directory inside the cloned repo:

```
glitch/rego/rego_python/src/rego_python/bin/
```

To use GLITCH for Chef, you also need Ruby and its Ripper package installed.

### OPA

Follow the [OPA installation instructions](https://www.openpolicyagent.org/docs#running-opa) to install the OPA CLI.

### KICS (optional, Ansible only)

KICS is supported as an alternative analysis tool for Ansible rules. The pipeline installs it automatically when `--analysis-tool kics` is used (requires [Go](https://golang.org/dl/)). You can also install KICS yourself and ensure `kics` is on PATH.

Generated KICS queries are written to `validation/KICS/queries/Ansible/common/<type_name>/`.

---

## Usage

### CWE mode

Generate a rule from a CWE description (loaded from `prompt_data/cwes/CWE-<n>.json`):

```bash
python llm_interaction.py <model> --cwe <n> --type-name <type_name> --experiment-name <name>
```

Example:

```bash
python llm_interaction.py xiaomi/mimo-v2.5-pro --cwe 259 --type-name sec_hard_pass --experiment-name my_experiment
```

### Description mode

Generate a rule from a natural language description (loaded from `prompt_data/descriptions/<type_name>.txt`):

```bash
python llm_interaction.py <model> --description --type-name <type_name> --experiment-name <name>
```

Example:

```bash
python llm_interaction.py xiaomi/mimo-v2.5-pro --description --type-name sec_hard_pass --experiment-name my_experiment
```

To add a new type, create `prompt_data/descriptions/<type_name>.txt` with a short description of what to detect.

### Common options

| Flag | Description |
|---|---|
| `--provider openrouter\|bedrock` | LLM provider to use (default: `openrouter`) |
| `--analysis-tool glitch\|kics` | Analysis tool to use (default: `glitch`) |
| `--semantic-examples-dir <dir>` | Override the default static examples directory |
| `--use-llm-examples` | Generate semantic examples via LLM instead of loading from disk |
| `--use-cwe-text` / `--use-description-text` | Skip LLM distillation and use the input text directly as the condition |
| `--condition-only` | Only generate and save the distilled condition, then exit |
| `--validation-history-iterations N` | Keep only the N most recent validation iterations in context (`-1` keeps all) |
| `--validation-history-pinned-messages M` | Always keep the first M messages regardless of the iteration window (default: 1) |
| `--skip-semantic-check` | Run syntax validation only |
| `--no-ir-slicing` | Disable IR slicing; pass the full IR to the LLM on semantic check failures |
| `--use-rag` | Enable RAG for syntax error assistance |
| `--examples-model <model>` | Model to use for generating semantic-check examples (default: same as main model) |
| `--technologies <tech...>` | Only run semantic check on these technologies (e.g. `ansible chef`); omit to use all |

When using `--provider bedrock`, pass the Bedrock inference profile ID as the model argument (e.g. `global.anthropic.claude-sonnet-4-6`).

---

## Output structure

Outputs are written under `generated_rego/<experiment_name>/<model>/runs/<run_id>/`.

- Run IDs are sequential (`run_001`, `run_002`, ...). A new run is created only after the current rule already exists in all previous runs.
- The Rego file is named `<rule_id>.rego`, where `rule_id` is `cwe_<n>` for CWE mode or `<type_name>` for description mode.
- JSON logs are written to `runs/<run_id>/logs/`.
- LLM-generated examples (when `--use-llm-examples` is enabled) are saved to `runs/<run_id>/generated_examples/<type_name>/`.

Static semantic examples live in `validation/examples/<type_name>/`.

---

## Batch running

### `run_all_cwes.sh` — CWE mode

```bash
./run_all_cwes.sh <model> <experiment_name> <examples_dir> <analysis_tool> <validation_history_iterations> [--max-runs N] [--provider openrouter|bedrock] <cwe1> [cwe2 ...]
```

Example:

```bash
./run_all_cwes.sh openai/gpt-5.2-codex my_experiment validation/examples_extension glitch -1 --max-runs 5 259 319 546
./run_all_cwes.sh global.anthropic.claude-sonnet-4-6 my_experiment validation/examples_extension glitch -1 --provider bedrock 259 319 546
```

Any flags after the positional arguments are forwarded directly to `llm_interaction.py` (e.g. `--skip-semantic-check`, `--no-ir-slicing`, `--use-rag`).

### `run_all_descriptions.sh` — Description mode

```bash
./run_all_descriptions.sh <model> <experiment_name> <examples_dir> <analysis_tool> <validation_history_iterations> [--max-runs N] [--provider openrouter|bedrock] <type_name1> [type_name2 ...]
```

Example:

```bash
./run_all_descriptions.sh openai/gpt-5.2-codex my_experiment validation/examples glitch -1 --max-runs 5 sec_hard_pass sec_https
./run_all_descriptions.sh global.anthropic.claude-sonnet-4-6 my_experiment validation/examples glitch -1 --provider bedrock sec_hard_pass sec_https
```

Both scripts retry failed runs up to `--max-runs` times (default: 1, overridable via `MAX_RUNS` env var) and report failures at the end. The provider defaults to `openrouter` and can also be set via the `PROVIDER` environment variable.

Any flags after the known positional/optional arguments are forwarded directly to `llm_interaction.py`.

### `run_kics_issues_combinations.sh` — KICS issue combinations

Runs four predefined combinations of KICS issue positive-file pairs through `run_all_descriptions.sh`. Each combination selects specific positive example files from `validation/examples_kics_issue/` and assembles a temporary examples directory before invoking the pipeline. Results are collected under `generated_rego/kics_issue_tests/`.

```bash
./run_kics_issues_combinations.sh <model> <validation_history_iterations> [--max-runs N] [--provider openrouter|bedrock]
```

Example:

```bash
./run_kics_issues_combinations.sh xiaomi/mimo-v2.5-pro -1 --max-runs 5
./run_kics_issues_combinations.sh global.anthropic.claude-sonnet-4-6 -1 --max-runs 5 --provider bedrock
```

---

## Deploying rules: `prepare_rules.py`

Scans an experiment's runs and deploys the first passing rule per entry in the mapping. Rules with no passing run are skipped.

```bash
python prepare_rules.py --analysis-tool <glitch|kics> --experiment-dir generated_rego/<experiment>/<model> --mapping mapping.json
```

The mapping is a list of `type_name` → `rego_file` entries, where `rego_file` gives the rule ID (e.g. `cwe_259.rego` for CWE mode, `sec_hard_pass.rego` for description mode):

```json
[
    {"type_name": "sec_hard_pass", "rego_file": "cwe_259.rego"},
    {"type_name": "sec_https",     "rego_file": "cwe_319.rego"}
]
```

Use `--only-cwe` to deploy only selected CWEs:

```bash
python prepare_rules.py --analysis-tool glitch --experiment-dir generated_rego/my_experiment/mimo-v2.5-pro --mapping glitch_rego_mapping.json --only-cwe 259 319
```

Before writing, the script removes any previously deployed rules for the mapped type names.

---

## Validation history

During iterative repair, the full conversation history is kept by default. Pass `-1` to `--validation-history-iterations` to explicitly preserve all history (same as omitting the flag). Use a positive `N` to keep only the N most recent iterations, or `0` to keep only the pinned messages. `--validation-history-pinned-messages M` controls how many leading messages are always preserved (default: 1).
