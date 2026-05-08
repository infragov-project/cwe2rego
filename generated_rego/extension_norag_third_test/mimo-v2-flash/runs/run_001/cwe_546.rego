package glitch

import data.glitch_lib

suspicious_regex_patterns := {
    ".*\\bTODO\\b.*",
    ".*\\bFIXME\\b.*",
    ".*\\bHACK\\b.*",
    ".*\\bLATER\\b.*",
    ".*\\bLATER2\\b.*",
    ".*\\bTEMP\\b.*",
    ".*\\bTEMPORARY\\b.*",
    ".*\\bSECURITY\\b.*",
    ".*\\bINSECURE\\b.*",
    ".*\\bDO NOT DEPLOY\\b.*",
    ".*\\bHARDENING\\b.*",
    ".*\\bSECURITY_BYPASS\\b.*",
    ".*\\bBUG\\b.*",
    ".*\\bWORKAROUND\\b.*",
    ".*\\bQUICKFIX\\b.*",
    ".*\\bNOSEC\\b.*",
    ".*\\bDEBUG\\b.*",
    ".*\\bVERBOSE\\b.*",
    ".*\\bDANGER\\b.*",
    ".*\\bCAUTION\\b.*",
    ".*\\bWARNING\\b.*",
    ".*\\bNOTE\\b.*",
    ".*\\bdeprecated\\b.*",
    ".*issues/.*",
    ".*tracker\\..*",
    ".*cannot change.*",
    ".*break the cookbook.*"
}

contains_suspicious_comment(text) {
    pattern := suspicious_regex_patterns[_]
    regex.match(pattern, text)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    contains_suspicious_comment(comment.content)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment indicating incomplete logic or security bypass - May contain temporary fixes, ignored errors, or intentional security bypasses. (CWE-546)"
    }
}