package glitch

import data.glitch_lib

suspicious_pattern := "(?i)(\\bTODO\\b|\\bFIXME\\b|\\bHACK\\b|\\bXXX\\b|\\bBUG\\b|\\bWORKAROUND\\b|\\bTEMPORARY\\b|\\bTEMP\\b|\\bKLUDGE\\b|\\bNOTE\\b|\\bdeprecated\\b|/issues/|disable security|remove before production|not secure|fix later|bypass|insecure|vulnerable|open port|allow all|should be encrypted|hardcoded|change this|replace this|placeholder|testing only|not implemented|missing authentication|needs review)"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    regex.match(suspicious_pattern, comment.content)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment detected - Comments may reveal sensitive information about security deficiencies, incomplete configurations, or known security gaps. (CWE-615)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    regex.match(suspicious_pattern, comment.code)
    not regex.match(suspicious_pattern, comment.content)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment detected - Comments may reveal sensitive information about security deficiencies, incomplete configurations, or known security gaps. (CWE-615)"
    }
}