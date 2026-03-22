package glitch

import data.glitch_lib

suspicious_keywords := [
    "TODO", "FIXME", "HACK", "BUG", "XXX",
    "TEMP", "TEMPORARY", "WORKAROUND", "KLUDGE",
    "LATER", "NOSONAR", "NOSEC", "INSECURE",
    "UNSAFE", "DISABLED", "HARDCODED", "PLACEHOLDER",
    "CHANGE_ME", "UPDATE_ME", "REMOVE_BEFORE_PROD",
    "BYPASS", "SKIP_AUTH", "NO_AUTH", "IGNORE",
    "OPEN_TO_ALL", "REVIEW", "NOTE", "WARNING",
    "BROKEN", "BREAK", "DEPRECATED"
]

comment_is_suspicious(content) {
    keyword := suspicious_keywords[_]
    regex.match(sprintf("(?i).*\\b%s\\b.*", [keyword]), content)
}

comment_is_suspicious(content) {
    regex.match("(?i).*/issues?/[0-9]+.*", content)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    comment_is_suspicious(comment.content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment detected - Comments indicating deferred security decisions, temporary misconfigurations, or acknowledged vulnerabilities. (CWE-546)"
    }
}