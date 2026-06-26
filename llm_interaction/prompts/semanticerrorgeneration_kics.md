You are a security expert with extensive Rego expertise. Please rewrite the following rule since it did not correctly detect the security check in the provided Ansible intermediate representation(s). Only return the Rego rule, ready to be used, and nothing else. No extra characters or words that do not conform to Rego syntax. The rule must use package Cx and define CxPolicy[result] with the same format as KICS examples.

**Rule to fix:**
```
{{rego_rule}}
```

The rule must detect the vulnerability in Ansible IaC configurations. Below are the intermediate representations where detections failed:

{% for failure in failures %}
**Language: {{failure.iac_language}}**

{% if failure.missing_lines %}
The lines that should have been detected are:
{% for line in failure.missing_lines %}
- Line {{line}}
{% endfor %}
{% endif %}

{% if failure.false_positives %}
The lines that were incorrectly flagged (false positives) are:
{% for line in failure.false_positives %}
- Line {{line}}
{% endfor %}
{% endif %}

Relevant lines from the original Ansible file (±3 lines of context around each flagged line):
```
{{failure.original_file_windowed}}
```

The intermediate representation in Kics is:
```
{{failure.ir_file}}
```

{% endfor %}

The code you generate must be capable of capturing this check in all of these scenarios and many others of the same type, so do not hardcode to these cases and generalize appropriately.

Requirements:
- Package must be Cx. Rule must be CxPolicy[result].
- Use input.document[i].playbooks[_] for playbook-level checks and ansLib.tasks[id][t] for task-level checks (import data.generic.ansible as ansLib, data.generic.common as commonLib).
- Keep the result object format as in the examples (documentId, searchKey, issueType, keyExpectedValue, keyActualValue).
- Keep the result object format as in the examples (documentId, searchKey, issueType, keyExpectedValue, keyActualValue).
- Avoid overly large scripts; prefer focused conditions.
- The rule should be as general as possible, avoiding hardcoding to the failures presented.
