package glitch

import data.glitch_lib

suspicious_patterns := {"TODO", "FIXME", "HACK", "BUG", "LATER", "LATER2", "NOTE", "XXX", "WORKAROUND", "TEMP", "KLUDGE", "bypass security", "ignore validation", "hardcoded credential", "no auth check", "skip TLS", "test only", "incomplete", "placeholder", "not implemented", "error handling missing", "TBD", "REVIEW", "deprecated", "issues", "tracker", "break", "cannot change"}

matches_suspicious_pattern(content) {
    pattern := suspicious_patterns[_]
    glitch_lib.contains(content, pattern)
}

Glitch_Analysis[result] {
    walk(input, [_, node])
    node.ir_type == "UnitBlock"
    comment := node.comments[_]
    matches_suspicious_pattern(comment.content)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": node.path,
        "description": "Suspicious comment found in IaC script - Comments with keywords like TODO, FIXME, etc., may indicate incomplete security controls or misconfigurations. (CWE-546)"
    }
}