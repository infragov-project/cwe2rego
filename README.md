# cwe2rego
Repository that works on converting CWEs to Rego rules for GLITCH framework


# Installation

## GLITCH
This system is designed to work with the [GLITCH](https://github.com/sr-lab/GLITCH) tool. For it to work, you need to do the following command:

```
mkdir validation/GLITCH
git clone https://github.com/sr-lab/GLITCH.git validation/GLITCH
```

## Install dependencies
To install the dependecies, use the requirements.txt:

```
python -m pip install -r requirements.txt
```

## Install OPA

Follow the instructions present [here](https://www.openpolicyagent.org/docs#running-opa) to install OPA CLI.

## Experiment naming for generated files

`llm_interaction.py` requires `--experiment-name` to tag generated Rego and JSON log files.

Example:

```bash
python llm_interaction.py xiaomi/mimo-v2-flash --cwe 250 --type-name sec_def_admin --experiment-name false_positives --use-llm-examples
```

This writes outputs grouped under `generated_rego/<experiment_name>/<model_name>/`.
The Rego filename is `cwe_<cwe>.rego` and logs are written under `generated_rego/<experiment_name>/<model_name>/logs/`.

Outputs are grouped first by experiment and then by model, under `generated_rego/<experiment_name>/<model_name>/`.

When `--use-llm-examples` is enabled, generated examples are saved under `generated_rego/<experiment_name>/<model_name>/generated_examples/CWE-<cwe>/`.