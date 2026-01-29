You are a security expert with extensive Rego expertise. Considering the following information, write a Rego V0 rule for the GLITCH framework to detect the CWE weakness presented. The rule needs to have the name ```Glitch_Analysis``` and return the same format as the examples.

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
