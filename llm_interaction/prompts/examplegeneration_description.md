You are a security expert. Generate Infrastructure as Code examples that exhibit the following weakness. The examples will be used to verify that a Rego-based linter correctly detects the smell.

**Rule: {{ type_name }}**

Weakness description:
```
{{ condition_text }}
```

Generate a JSON array of examples. Each example must be a single object with:
- **file**: string, filename with a supported extension ({{ supported_extensions_text }})
- **content**: string, the full file content of the IaC snippet

Produce at least 6 examples covering only these IaC technologies: {{ target_technologies_text }}.

Rules:
-  Avoid examples where the smell is caused only by missing configuration or omission.
- The generated examples should be as general as possible.
- Output valid JSON only. No markdown and no explanation.
