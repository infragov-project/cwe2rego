package glitch

import data.glitch_lib

suspicious_keywords := {"FIXME", "TODO", "XXX", "HACK", "BUG", "DEFECT", "WORKAROUND", "LATER", "TEMP", "DEBUG", "REMOVE", "DEPRECATED", "SECURITY", "INSECURE", "AUTH", "PERMISSION"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    comment := parent.comments[_]
    content := comment.content
    
    contains_suspicious(content)
    
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment detected - Comments containing markers like TODO, FIXME, HACK, etc. may indicate incomplete or insecure implementation. (CWE-546)"
    }
}

contains_suspicious(content) {
    keyword := suspicious_keywords[_]
    regex.match(sprintf("(?i)\\b%s\\b", [keyword]), content)
}