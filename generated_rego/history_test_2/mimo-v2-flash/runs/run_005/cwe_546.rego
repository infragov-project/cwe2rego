package glitch

import data.glitch_lib

suspicious_keywords := {"BUG", "HACK", "FIXME", "LATER", "LATER2", "TODO", "XXX", "TEMP", "DEBUG", "NOTE", "WORKAROUND", "bypass", "hard-coded credential", "missing validation", "insecure default", "disable security", "placeholder", "dummy"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    comment := parent.comments[_]
    content := comment.content
    
    contains_suspicious := false
    some keyword in suspicious_keywords
    contains_suspicious := contains_suspicious or glitch_lib.contains(content, keyword)
    
    contains_suspicious == true
    
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment indicating incomplete or insecure code - Comments with keywords like FIXME, TODO, bypass, hard-coded, etc. may signal unaddressed security gaps. (CWE-546)"
    }
}