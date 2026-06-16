package glitch

import data.glitch_lib

suspicious_patterns := {"TODO", "FIXME", "BUG", "HACK", "LATER", "XXX", "OPTIMIZE", "REFACTOR", "WORKAROUND", "TEMPORARY", "INCOMPLETE", "DIRTY", "KLUDGE", "No authentication", "Default password", "Insecure", "Vulnerable", "Bypass", "Hardcoded credential", "No validation", "Skip check", "Memory leak", "Race condition", "Slow", "Timeout", "Unstable"}

Glitch_Analysis[result] {
    walk(input, [path, node])
    node.ir_type == "Comment"
    node.line > 0
    pattern := suspicious_patterns[_]
    contains(node.content, pattern)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent.path,
        "description": "Suspicious comment found that may indicate a bug, incomplete functionality, or security weakness. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    walk(input, [path, node])
    node.ir_type != "Comment"
    node.code != ""
    lines := split(node.code, "\n")
    line := lines[_]
    regex.match("^[[:space:]]*#", line)
    pattern := suspicious_patterns[_]
    contains(line, pattern)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent.path,
        "description": "Suspicious comment found that may indicate a bug, incomplete functionality, or security weakness. (CWE-546)"
    }
}