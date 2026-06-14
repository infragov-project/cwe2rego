You are a security expert. Identify smelly lines for the weakness below in the provided Infrastructure as Code files.

**Rule: {{ type_name }}**

Weakness description:
```
{{ condition_text }}
```

The input files are provided as a list of objects. Each object has:
- `file`: file name
- `numbered_content`: the file content where each line begins with its line number and a colon (example: `12: some text`)

Input files:
{% for item in files %}
File: {{ item.file }}
```text
{{ item.numbered_content }}
```
{% endfor %}

Return a JSON array with one object per input file. Each object must have:
- `file`: string, same file name as input
- `lines`: array of integers with the line numbers that contain the smell

Reference annotated examples are provided only to show the expected annotation format and granularity. Use them as examples of annotation style, not as evidence for the current weakness semantics.

Reference examples:
{% for item in reference_examples %}
Reference file: {{ item.file }}
```text
{{ item.numbered_content }}
```
Annotated lines: {{ item.annotated_lines }}
{% endfor %}

Rules:
- Use line numbers from the numbered content prefix.
- Return all and only files from the input.
- If a file has no smell lines, return an empty array for `lines`.
- When a smelly line is inside a embeded script (e.g configuration files, shell scripts) point to the line number where the shell script begins in the IaC file, not the actual line where the smell occurs
- Output valid JSON only. No markdown and no explanation.
