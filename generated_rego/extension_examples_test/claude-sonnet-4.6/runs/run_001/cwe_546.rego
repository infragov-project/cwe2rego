package glitch

import data.glitch_lib

suspicious_keywords := [
    "TODO", "FIXME", "HACK", "XXX", "LATER", "TEMP", "WORKAROUND",
    "KLUDGE", "BANDAID", "INSECURE", "HARDCODED", "DISABLED",
    "PLACEHOLDER", "DUMMY", "DEBUG", "DEPRECATED", "LEGACY",
    "DANGER", "WARNING", "BUG", "NOTE", "CHANGE ME", "CHANGE THIS",
    "REMOVE THIS", "REMOVE LATER", "TEST ONLY", "OVERPERMISSIVE",
    "SECURITY ISSUE", "SECURITY RISK", "NOT SECURE",
    "DO NOT USE IN PRODUCTION", "TOO BROAD", "COMMENTED OUT"
]

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    keyword := suspicious_keywords[_]
    glitch_lib.contains(comment.content, keyword)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment detected - Comments may indicate incomplete, insecure, or deferred security configurations. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    regex.match("(?i).*https?://[^\\s]*/issues/[0-9]+.*", comment.content)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment with issue tracker reference detected - Comments referencing unresolved issues may indicate deferred security fixes. (CWE-546)"
    }
}