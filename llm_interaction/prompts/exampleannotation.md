You are a security expert. Identify smelly lines for the weakness below in the provided Infrastructure as Code files.

A smelly line is the starting line of the smallest construct that reveals the weakness. Report that line, never a line below or above it.

When a single construct spans multiple lines, report its first line even if the offending value appears further down. When the weakness lies in one specific element of a larger structure, such as a single entry in a multi-line list, report that element's line rather than the line of the enclosing structure. When the weakness is the absence of something, such as a missing configuration parameter, report the starting line of the parent construct where it should have appeared. This applies to all formats, including configuration files and shell scripts.

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
- Output valid JSON only. No markdown and no explanation.
