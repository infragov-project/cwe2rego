package glitch

import data.glitch_lib

suspicious_keywords := {"TODO", "HACK", "FIXME", "BUG", "INSECURE", "TEMPORARY", "WORKAROUND", "SECURITYISSUE", "VULNERABILITY", "QUICKFIX", "RISKY", "OVERRIDE", "NOTE"}

has_suspicious_comment(content) {
    keyword := suspicious_keywords[_]
    regex.match(sprintf("(?i).*\\b%s\\b.*", [keyword]), content)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    comment := parent.comments[_]
    has_suspicious_comment(comment.content)
    
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment found in IaC file - Comment contains keywords indicating potential security issues such as unresolved fixes or insecure practices."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, n])
    code_str := n.code
    code_str != ""
    lines := split(code_str, "\n")
    some i
    line := lines[i]
    regex.match("^[[:space:]]*(#|//|/\\*).*$", line)
    has_suspicious_comment(line)
    
    comment_line := n.line + i
    
    result := {
        "type": "sec_susp_comm",
        "element": {
            "ir_type": "Comment",
            "line": comment_line,
            "code": line,
            "content": line
        },
        "path": parent.path,
        "description": "Suspicious comment found in IaC file - Comment contains keywords indicating potential security issues such as unresolved fixes or insecure practices."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, n])
    code_str := n.code
    code_str != ""
    lines := split(code_str, "\n")
    some i
    line := lines[i]
    regex.match(".*(#|//|/\\*).*", line)
    comment_part := regex.replace("^(.*?)(#|//|/\\*)(.*)$", line, "$3")
    comment_part != ""
    has_suspicious_comment(comment_part)
    
    comment_line := n.line + i
    
    result := {
        "type": "sec_susp_comm",
        "element": {
            "ir_type": "Comment",
            "line": comment_line,
            "code": line,
            "content": comment_part
        },
        "path": parent.path,
        "description": "Suspicious comment found in IaC file - Comment contains keywords indicating potential security issues such as unresolved fixes or insecure practices."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, n])
    n.ir_type == "String"
    n.value != ""
    lines := split(n.value, "\n")
    some i
    line := lines[i]
    regex.match("^[[:space:]]*(#|//|/\\*).*$", line)
    has_suspicious_comment(line)
    
    comment_line := n.line + i
    
    result := {
        "type": "sec_susp_comm",
        "element": {
            "ir_type": "Comment",
            "line": comment_line,
            "code": line,
            "content": line
        },
        "path": parent.path,
        "description": "Suspicious comment found in IaC file - Comment contains keywords indicating potential security issues such as unresolved fixes or insecure practices."
    }
}