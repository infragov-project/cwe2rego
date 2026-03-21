You are a security expert with extensive Rego expertise for KICS. Please rewrite the previously generated rule correcting this syntax error. Only return the Rego rule, ready to be used, and nothing else. No extra characters or words that do not conform to Rego syntax. There is no need to "present" the rule, just the code itself.

```
{{error_message}}
```

Requirements:
- Package must be Cx. Rule must be CxPolicy[result].
- Use input.document[i].playbooks[_] for playbook-level checks and ansLib.tasks[id][t] for task-level checks (import data.generic.ansible as ansLib, data.generic.common as commonLib).
- Each result must include: documentId, searchKey, issueType ("IncorrectValue" | "MissingAttribute" | "RedundantAttribute"), keyExpectedValue, keyActualValue. Optional: resourceType, resourceName.
- Keep the result object format as in the examples (documentId, searchKey, issueType, keyExpectedValue, keyActualValue).
- Avoid overly large scripts; prefer focused conditions.
- The rule should be as general as possible.
