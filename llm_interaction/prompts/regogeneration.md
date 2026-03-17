You are a security expert with extensive Rego expertise. Considering the following information, write a Rego rule for the GLITCH framework to detect the CWE weakness presented. The rule needs to have the name ```Glitch_Analysis``` and return the same format as the examples. Only return the Rego rule, ready to be used, and nothing else. No extra characters or words such as ` or rego, that do not conform to Rego syntax. There is no need to "present" the rule, just the code itself.

Considering this CWE condition, which briefly explains how the CWE-{{cwe}} may appear in Infrastructure as Code scripts:

```
{{cwe_condition}}
```

The Rego rule will have as input the Intermediate Representation of GLITCH for the IaC files, which has the following structure:

```
{{ir}}
```

For easier rule creation, you can use the following rego library to traverse the Intermediate Representation, which you can import in the rule using ```import data.glitch_lib```:

```
{{rego_lib}}
```

As a reference, follow the shape of the provided rules. They need to have the name ```Glitch_Analysis``` and return the same format.

```
{{example_rule_1}}
```

```
{{example_rule_2}}
```

Things to pay attention:
- Avoid referencing data.security module with sets that are not confirmed to exist.
- Avoid generating too large rego scripts to avoid syntatic and semantic errors.
- Avoid referencing names and objects specific to certain providers such as AWS and Azure for the representation, since the IR is independent of such.
- In the Glitch IR, complex Values may also contain other complex Values, such as Hash within Hash and Hash within Array, besides containing primitive Values like String and Integer.
- The rule should be as general as possible.