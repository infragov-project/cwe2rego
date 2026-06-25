package glitch

import data.glitch_lib

suspicious_keywords := [
    "TODO", "FIXME", "HACK", "BUG", "XXX", "WORKAROUND",
    "TEMP", "TEMPORARY", "KLUDGE", "LATER", "LATER2",
    "HARDCODED", "INSECURE", "DISABLED", "NOCHECK", "NO_CHECK",
    "NOSEC", "NOSONAR", "PASSWORD", "SECRET", "CRED",
    "BYPASS", "REVIEW", "REMOVE", "DELETE"
]

comment_is_suspicious(comment) {
    keyword := suspicious_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [keyword]), comment.content)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, comment])
    comment.ir_type == "Comment"
    comment_is_suspicious(comment)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment detected - Comments containing keywords such as TODO, FIXME, HACK, INSECURE, or PASSWORD may indicate incomplete, insecure, or problematic configurations. (CWE-546)"
    }
}