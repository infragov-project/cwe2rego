You are a security expert with extensive Rego expertise. Please rewrite the previously generated rule since it did not detect the security smell in the following intermediate representation and considering this is Rego V0. Only return the Rego rule, ready to be used, and nothing else. No extra characters or words such as ` or rego, that do not conform to Rego syntax. There is no need to "present" the rule, just the code itself.

The file is of the language ```{{iac_language}}```.

The line that should have been detected is ```{{line_number}}```.

The intermediate representation of the file in GLITCH is the following:

```
{{ir_file}}
```

The code you generate must be capable of capturing this smell and many others of the same type, so do not hardcode to this and try to generalize for several IaC techonlogies such as Ansible, Chef and Puppet.