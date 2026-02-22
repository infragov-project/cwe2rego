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