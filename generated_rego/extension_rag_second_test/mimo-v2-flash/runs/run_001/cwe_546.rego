package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    
    suspicious_keywords = {
        "BUG", "FIXME", "XXX", "ISSUE", "ERROR",
        "HACK", "TODO", "LATER", "TEMP", "QUICK FIX", "DIRTY",
        "SECURITY", "INCOMPLETE", "HARD-CODED", "INSECURE", "TODO: SECURE",
        "LATER2", "POSTPONE", "NEEDS REVIEW", "SECURITY TODO",
        "PERFORMANCE", "RACE CONDITION", "DEADLOCK", "ERROR HANDLING",
        "deprecated"
    }
    
    keyword := suspicious_keywords[_]
    glitch_lib.contains(comment.content, keyword)
    
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment detected indicating potential technical debt or unresolved issue (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    code_lines := split(node.code, "\n")
    line := code_lines[_]
    trimmed := trim(line, " ")
    
    comment_prefixes = {"#", "//", "/*"}
    prefix := comment_prefixes[_]
    startswith(trimmed, prefix)
    
    suspicious_keywords = {
        "BUG", "FIXME", "XXX", "ISSUE", "ERROR",
        "HACK", "TODO", "LATER", "TEMP", "QUICK FIX", "DIRTY",
        "SECURITY", "INCOMPLETE", "HARD-CODED", "INSECURE", "TODO: SECURE",
        "LATER2", "POSTPONE", "NEEDS REVIEW", "SECURITY TODO",
        "PERFORMANCE", "RACE CONDITION", "DEADLOCK", "ERROR HANDLING",
        "deprecated"
    }
    
    keyword := suspicious_keywords[_]
    glitch_lib.contains(trimmed, keyword)
    
    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent.path,
        "description": "Suspicious comment detected in AtomicUnit code (CWE-546)"
    }
}