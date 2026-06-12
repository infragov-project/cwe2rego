You are a security expert with extensive Rego expertise. Please rewrite the following rule correcting this syntax error. Only return the Rego rule, ready to be used, and nothing else. No extra characters or words that do not conform to Rego syntax. There is no need to "present" the rule, just the code itself.

**Rule to fix:**
```
{{rego_rule}}
```

**OPA error:**
```
{{error_message}}
```

You can use the following Rego reference documentation to help fix the error:

```
{{rag_context}}
```

Requirements:
- Package must be Cx. Rule must be CxPolicy[result].
- Use input.document[i].playbooks[_] for playbook-level checks and ansLib.tasks[id][t] for task-level checks (import data.generic.ansible as ansLib, data.generic.common as commonLib).
- Keep the result object format as in the examples (documentId, searchKey, issueType, keyExpectedValue, keyActualValue).
- Avoid overly large scripts; prefer focused conditions.
- The rule should be as general as possible.
