package glitch

import data.glitch_lib

suspicious_keywords := ["TODO", "FIXME", "HACK", "BUG", "LATER", "LATER2", "WORKAROUND", "XXX", "TEMP", "KLUDGE"]

is_suspicious_comment(content) {
    keyword := suspicious_keywords[_]
    regex.match(sprintf("(?i).*\\b%s\\b.*", [keyword]), content)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, comment])
    comment.ir_type == "Comment"
    is_suspicious_comment(comment.content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment found - Comments suggesting bugs, incomplete functionality, or weaknesses should be removed before deployment. (CWE-546)"
    }
}