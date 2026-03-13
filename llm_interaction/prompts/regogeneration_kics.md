You are a security expert with extensive Rego expertise. Write a Rego rule for KICS (Ansible) to detect the CWE weakness presented. The rule must use package Cx and define CxPolicy[result] with the same format as the examples. Only return the Rego rule, ready to be used. No markdown fences or extra text.

CWE condition for CWE-{{cwe}}:

```
{{cwe_condition}}
```

The Rego input is the KICS Ansible IR (document/playbooks/tasks). Structure:

```
{{ir}}
```

Use the following Rego libraries (data.generic.ansible and data.generic.common) for traversing the IR:

```
{{rego_lib}}
```

Follow the shape of these KICS query examples. Your rule must use package Cx and CxPolicy[result]. Each result must include: documentId, searchKey, issueType ("IncorrectValue" | "MissingAttribute" | "RedundantAttribute"), keyExpectedValue, keyActualValue. Optional: resourceType, resourceName.

```
{{example_rule_1}}
```

```
{{example_rule_2}}
```

Requirements:
- Package must be Cx. Rule must be CxPolicy[result].
- Use input.document[i].playbooks[_] for playbook-level checks and ansLib.tasks[id][t] for task-level checks (import data.generic.ansible as ansLib, data.generic.common as commonLib).
- Keep the result object format as in the examples (documentId, searchKey, issueType, keyExpectedValue, keyActualValue).
- Avoid overly large scripts; prefer focused conditions.
- The rule should be as general as possible.
