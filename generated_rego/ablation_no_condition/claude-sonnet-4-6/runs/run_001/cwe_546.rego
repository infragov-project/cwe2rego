package glitch

import data.glitch_lib

suspicious_keywords := ["TODO", "FIXME", "HACK", "BUG", "LATER", "LATER2", "XXX", "WORKAROUND", "KLUDGE", "NOCOMMIT", "NOTE", "WARN", "WARNING", "TEMP", "TEMPORARY", "BROKEN", "BREAK", "REVISIT", "DEPRECATED", "DEPRECATE"]

is_suspicious_comment(content) {
    keyword := suspicious_keywords[_]
    regex.match(sprintf("(?i).*\\b%s\\b.*", [keyword]), content)
}

is_suspicious_comment(content) {
    regex.match(`(?i).*/issues/[0-9]+.*`, content)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Comment"
    is_suspicious_comment(node.content)

    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": parent.path,
        "description": "Suspicious comment found - Comments suggesting bugs, incomplete functionality, or weaknesses should be addressed before deployment. (CWE-546)"
    }
}