package glitch

import data.glitch_lib

suspicious_keywords := {"TODO", "HACK", "FIXME", "BUG", "INSECURE"}

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
        "description": "Suspicious keyword found in comment indicating a potential security issue. (CWE-732)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type != "String"
    node.ir_type != "Comment"
    node.code != ""
    
    keyword := suspicious_keywords[_]
    lines := split(node.code, "\n")
    line := lines[_]
    comment_part := regex.split("#", line)[1]
    comment_part != ""
    glitch_lib.contains(comment_part, keyword)
    
    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent.path,
        "description": "Suspicious keyword found in code comment indicating a potential security issue. (CWE-732)"
    }
}