package glitch

import data.glitch_lib

suspicious_patterns = {
    "(?i)\\bTODO\\b",
    "(?i)\\bFIXME\\b",
    "(?i)\\bHACK\\b",
    "(?i)\\bBUG\\b",
    "(?i)\\bLATER\\b",
    "(?i)\\bLATER2\\b",
    "(?i)\\bXXX\\b",
    "(?i)\\bTEMP\\b",
    "(?i)\\bWORKAROUND\\b",
    "(?i)AUTHENTICATION NEEDED",
    "(?i)ACCESS CONTROL MISSING",
    "(?i)ENCRYPTION WEAK",
    "(?i)NOT FOR PRODUCTION",
    "(?i)INSECURE BY DESIGN",
    "(?i)BYPASS SECURITY",
    "(?i)EXPOSE",
    "(?i)LEAK",
    "(?i)VULNERABLE",
    "(?i)UNSAFE",
    "(?i)SENSITIVE DATA",
    "(?i)DEBUG MODE ON",
    "(?i)TEST CREDENTIALS",
    "(?i)LEAVE PASSWORDS HERE TEMPORARILY",
    "(?i)http.*issues",
    "(?i)tracker",
    "(?i)deprecated",
    "(?i)break"
}

is_suspicious_comment(comment) {
    pattern := suspicious_patterns[_]
    regex.match(pattern, comment.content)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    is_suspicious_comment(comment)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment indicating incomplete security functionality or vulnerability. (CWE-546)"
    }
}