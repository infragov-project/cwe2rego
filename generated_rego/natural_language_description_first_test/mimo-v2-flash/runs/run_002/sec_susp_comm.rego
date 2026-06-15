package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check direct comments in the UnitBlock
    comment := parent.comments[_]
    suspicious_keywords := {"TODO", "HACK", "FIXME", "BUG", "INSECURE"}
    glitch_lib.contains(comment.content, suspicious_keywords[_])
    
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious keyword in comment indicating potential security issue (e.g., TODO, HACK, FIXME, BUG, INSECURE)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for comments in code strings of other nodes
    walk(parent, [path, node])
    node.ir_type != "Comment"
    node.code != ""
    
    suspicious_keywords := {"TODO", "HACK", "FIXME", "BUG", "INSECURE"}
    code_lines := split(node.code, "\n")
    line := code_lines[_]
    
    # Check if line is a comment (starts with optional whitespace followed by #)
    regex.match("^\\s*#", line)
    
    # Check if comment contains suspicious keywords
    keyword := suspicious_keywords[_]
    glitch_lib.contains(line, keyword)
    
    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent.path,
        "description": "Suspicious keyword in comment indicating potential security issue (e.g., TODO, HACK, FIXME, BUG, INSECURE)"
    }
}