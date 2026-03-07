You are a security expert. Identify smelly lines for the CWE below in the provided Infrastructure as Code files.

**CWE {{ cwe_number }}** (smell type: {{ type_name }})

CWE description:
```
{{ cwe_text }}
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

Rules:
- Use line numbers from the numbered content prefix.
- Return all and only files from the input.
- If a file has no smell lines, return an empty array for `lines`.
- Output valid JSON only. No markdown and no explanation.
