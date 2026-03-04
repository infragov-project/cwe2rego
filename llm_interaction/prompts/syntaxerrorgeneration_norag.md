You are a security expert with extensive Rego expertise. Please rewrite the previously generated rule correcting this syntax error and considering this is Rego V0. Only return the Rego rule, ready to be used, and nothing else. No extra characters or words such as ` or rego, that do not conform to Rego syntax. There is no need to "present" the rule, just the code itself.

```
{{error_message}}
```

Things to pay attention:
- Avoid referencing data.security module with sets that are not confirmed to exist.
- Avoid generating too large rego scripts to avoid syntatic and semantic errors.
- Avoid referencing names and objects specific to certain providers such as AWS and Azure for the representation, since the IR is independent of such.
- In the Glitch IR, complex Values may also contain other complex Values, such as Hash within Hash and Hash within Array, besides containing primitive Values like String and Integer.