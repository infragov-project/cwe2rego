You are a security expert with extensive Rego expertise. Please rewrite the previously generated rule since it did not correctly detect the security smell in the following intermediate representation(s) and considering this is Rego V0. Only return the Rego rule, ready to be used, and nothing else. No extra characters or words such as ` or rego, that do not conform to Rego syntax. There is no need to "present" the rule, just the code itself.

The rule must detect the vulnerability across {% if target_technologies|length == 1 %}this IaC technology{% else %}these IaC technologies{% endif %}: {{ target_technologies_text }}. Below are the intermediate representations where detections failed:

{% for failure in failures %}
**Language: {{failure.iac_language}}**

{% if failure.missing_lines %}
The lines that should have been detected are:
{% for line in failure.missing_lines %}
- Line {{line}}
{% endfor %}
{% endif %}

{% if failure.false_positives %}
The lines that were incorrectly flagged (false positives) are:
{% for line in failure.false_positives %}
- Line {{line}}
{% endfor %}
{% endif %}

The intermediate representation in GLITCH is:
```
{{failure.ir_file}}
```

{% endfor %}

The code you generate must be capable of capturing this smell in all of these scenarios and many others of the same type, so do not hardcode to these cases and generalize for {% if target_technologies|length == 1 %}the selected IaC technology{% else %}the selected IaC technologies{% endif %}: {{ target_technologies_text }}.

Things to pay attention:
- Avoid referencing data.security module with sets that are not confirmed to exist.
- Avoid generating too large rego scripts to avoid syntatic and semantic errors.
- Avoid referencing names and objects specific to certain providers such as AWS and Azure for the representation, since the IR is independent of such.
- In the Glitch IR, complex Values may also contain other complex Values, such as Hash within Hash and Hash within Array, besides containing primitive Values like String and Integer.