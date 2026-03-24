package glitch

import data.glitch_lib

suspicious_keywords := {"BUG", "HACK", "FIXME", "LATER", "TODO", "TEMP", "WORKAROUND", "INSECURE", "VULNERABLE", "EXPOSED", "CRITICAL", "URGENT", "NOTE", "deprecated", "break", "tracker", "issues"}

is_suspicious_comment(content) {
    keyword := suspicious_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [keyword]), content)
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
        "description": "Suspicious comment indicating incomplete functionality, security gaps, or unresolved issues (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Comment"
    is_suspicious_comment(node.content)
    
    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent.path,
        "description": "Suspicious comment indicating incomplete functionality, security gaps, or unresolved issues (CWE-546)"
    }
}