package glitch

import data.glitch_lib

general_keywords = {"TODO", "FIXME", "HACK", "LATER", "XXX", "BUG", "WORKAROUND", "NOTE", "Missing", "No authentication", "Hardcoded", "DEBUG", "Incomplete", "pending", "Not production-ready", "known vulnerabilities", "temporarily", "disable", "break the cookbook", "deprecated"}
url_keywords = {"tracker", "issue"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    k := general_keywords[_]
    glitch_lib.contains(comment.content, k)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment found in IaC script - indicates incomplete security controls, bugs, or workarounds. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    k := url_keywords[_]
    glitch_lib.contains(comment.content, k)
    glitch_lib.contains(comment.content, "http://")

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment found in IaC script - indicates incomplete security controls, bugs, or workarounds. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.name == "comments"
    node.value.ir_type == "String"
    content := node.value.value
    k := general_keywords[_]
    glitch_lib.contains(content, k)

    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent.path,
        "description": "Suspicious comment in metadata field - indicates incomplete security controls, bugs, or workarounds. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.name == "comments"
    node.value.ir_type == "String"
    content := node.value.value
    k := url_keywords[_]
    glitch_lib.contains(content, k)
    glitch_lib.contains(content, "http://")

    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent.path,
        "description": "Suspicious comment in metadata field - indicates incomplete security controls, bugs, or workarounds. (CWE-546)"
    }
}