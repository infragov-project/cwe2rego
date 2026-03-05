You are a security expert. Generate Infrastructure as Code examples that exhibit the following CWE weakness. The examples will be used to verify that a Rego-based linter correctly detects the smell.

**CWE {{ cwe_number }}** (smell type: {{ type_name }})

CWE description:
```
{{ cwe_text }}
```

Generate a JSON array of examples. Each example must be a single object with:
- **file**: string, filename with a supported extension (`.yml`, `.yaml`, `.rb`, or `.pp`)
- **content**: string, the full file content of the IaC snippet
- **lines**: array of integers, the line number(s) in that file where the smell appears

Produce at least 6 examples covering different technologies (Ansible, Chef, Puppet). Output only valid JSON, no markdown or explanation.
