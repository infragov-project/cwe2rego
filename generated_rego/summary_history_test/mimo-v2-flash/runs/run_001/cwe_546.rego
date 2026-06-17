package glitch

import data.glitch_lib

suspicious_keywords := {
    "TODO", "FIXME", "HACK", "BUG", "LATER", "LATER2", "XXX", "TEMP", "WORKAROUND", "NOTE",
    "insecure", "vulnerable", "bypass", "disable", "skip", "ignore", "relax", "open",
    "password", "secret", "key", "token", "credential", "hardcode", "exposed",
    "no auth", "no validation", "no encryption", "no firewall", "publicly accessible",
    "deprecated", "break", "tracker", "jira", "ticket"
}

contains_suspicious_keyword(content) {
    keyword := suspicious_keywords[_]
    glitch_lib.contains(content, keyword)
}

find_comments(node) = comments {
    comments := {c |
        walk(node, [path, n])
        n.ir_type == "Comment"
        c := n
    }
}

get_file_path(parent) = path {
    parent.path != ""
    path := parent.path
} {
    parent.path == ""
    path := parent.name
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    file_path := get_file_path(parent)
    file_path != ""
    
    comments := find_comments(parent)
    comment := comments[_]
    contains_suspicious_keyword(comment.content)
    
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": file_path,
        "description": "Suspicious comment found in IaC script - may indicate incomplete work or security risk (CWE-546)"
    }
}