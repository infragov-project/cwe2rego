package glitch

import data.glitch_lib

suspicious_patterns := {
    "(?i)\\bBUG\\b",
    "(?i)\\bHACK\\b",
    "(?i)\\bFIXME\\b",
    "(?i)\\bTODO\\b",
    "(?i)\\bLATER\\b",
    "(?i)\\bLATER2\\b",
    "(?i)\\bDEBUG\\b",
    "(?i)\\bWORKAROUND\\b",
    "(?i)\\bXXX\\b",
    "(?i)\\bTEMPORARY\\b",
    "(?i)\\bNOTE\\b",
    "(?i)\\bhard-?coded\\b",
    "(?i)\\bmissing\\b",
    "(?i)\\bskip\\b",
    "(?i)\\bignore\\b",
    "(?i)\\bcannot change\\b",
    "(?i)\\bbreak\\b",
    "(?i)\\bfor testing\\b",
    "(?i)\\bworkaround\\b",
    "(?i)\\btemporary\\b"
}

is_suspicious_comment(comment_content) {
    pattern := suspicious_patterns[_]
    regex.match(pattern, comment_content)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    is_suspicious_comment(comment.content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment indicating incomplete, risky, or insecure configuration (CWE-546)"
    }
}