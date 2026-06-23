package glitch

import data.glitch_lib

suspicious_comment_pattern := `(?i).*(\bTODO\b|TO-DO|\bFIXME\b|FIX-ME|\bLATER\b|\bPENDING\b|\bINCOMPLETE\b|\bPLACEHOLDER\b|\bSTUB\b|\bBUG\b|\bHACK\b|\bWORKAROUND\b|\bKLUDGE\b|\bBAD\b|\bBROKEN\b|\bDEFECT\b|\bWRONG\b|\bTEMP\b|\bTEMPORARY\b|\bDISABL\w*\b|\bBYPASS\b|\bSKIP\b|\bIGNORE\b|\bREMOVE\b|\bINSECURE\b|\bUNSAFE\b|\bFAKE\b|\bDUMMY\b|\bOVERRIDE\b|\bDANGEROUS\b|\bMYSTERY\b|\bNOTE\b|HARD.?CODED|\bnosec\b|\bnoqa\b|tfsec:ignore|\bDEPRECATED\b|CVE-[0-9]+-[0-9]+|DEFAULT.PASS|DEFAULT.CRED|CHANGE.THIS|CHANGE.ME|FOR.TESTING|TEST.ONLY|MEMORY.LEAK|RESOURCE.LEAK|DO.NOT.TOUCH|DO.NOT.CHANGE|ALLOW.ALL|OPEN.TO.ALL|NOT.IMPLEMENTED|NEED.AUTH|AUTHENTICATION.MISSING|PERFORMANCE.ISSUE|NOT.SAFE|DO.NOT.USE.IN.PRODUCTION|PUBLIC.FOR.NOW|/issues/[0-9]+).*`

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    regex.match(suspicious_comment_pattern, comment.content)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment detected - Comments may indicate deferred, incomplete, or knowingly insecure configurations. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Comment"
    regex.match(suspicious_comment_pattern, node.content)
    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent.path,
        "description": "Suspicious comment detected - Comments may indicate deferred, incomplete, or knowingly insecure configurations. (CWE-546)"
    }
}