package glitch

import data.glitch_lib

suspicious_keywords := {"TODO", "FIXME", "HACK", "WORKAROUND", "BUG", "LATER", "LATER2", "XXX", "HARDCODED", "NOSEC", "TODOSEC", "INSECURE"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    comment.ir_type == "Comment"
    keyword := suspicious_keywords[_]
    glitch_lib.contains(comment.content, keyword)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment found in IaC code. (CWE-546)"
    }
}