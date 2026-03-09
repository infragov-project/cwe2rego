You are a security expert with extensive Rego expertise. Write a Rego rule for KICS (Ansible) to detect the CWE weakness presented. The rule must use package Cx and define CxPolicy[result] with the same format as the examples. Only return the Rego rule, ready to be used. No markdown fences or extra text.

CWE condition for CWE-{{cwe}}:

```
{{cwe_condition}}
```

The Rego input is the KICS Ansible IR (document/playbooks/tasks). Structure:

```
{{ir}}
```

Use the following Rego library (data.generic.ansible and optionally data.generic.common) for traversing the IR:

```
{{rego_lib}}
```

Follow the shape of these KICS query examples. Your rule must use package Cx and CxPolicy[result]. Each result must include: documentId, searchKey, issueType ("IncorrectValue" | "MissingAttribute" | "RedundantAttribute"), keyExpectedValue, keyActualValue. Optional: resourceType, resourceName. You must include searchLine in every result: set it using common_lib.build_search_line with the path that locates the finding in the IR (e.g. ["playbooks", taskIndex, "fieldName"] for a task field). Without searchLine, KICS reports the finding on line 1 and semantic validation fails (missing detection on the real line, false positive on line 1).

```
{{example_rule_1}}
```

```
{{example_rule_2}}
```

Requirements:
- Package must be Cx. Rule must be CxPolicy[result].
- Use input.document[i].playbooks[_] for playbook-level checks and ansLib.tasks[id][t] for task-level checks (import data.generic.ansible as ansLib).
- Keep the result object format as in the examples (documentId, searchKey, issueType, keyExpectedValue, keyActualValue).
- Include searchLine in every CxPolicy result via common_lib.build_search_line(path, []), using the path that identifies the offending key in the IR (e.g. ["playbooks", t, "become_user"] for task-level become_user). This is required for KICS to report the correct source line; omitting it causes line 1 to be reported and fails semantic checks.
- Avoid overly large scripts; prefer focused conditions.
