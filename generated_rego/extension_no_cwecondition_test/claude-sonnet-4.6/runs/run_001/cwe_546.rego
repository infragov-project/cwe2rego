package glitch

import data.glitch_lib

suspicious_patterns := [
    "(?i)\\b(TODO|FIXME|HACK|BUG|LATER|LATER2|XXX|WORKAROUND|BROKEN|BREAK|NOTE|DEPRECATED|OBSOLETE)\\b",
    "https?://\\S+/issues/\\d+"
]

comment_is_suspicious(content) {
    pattern := suspicious_patterns[_]
    regex.match(pattern, content)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, comment])
    comment.ir_type == "Comment"

    comment_is_suspicious(comment.content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment found - Comments suggesting bugs, incomplete functionality, or weaknesses should be resolved before deployment. (CWE-546)"
    }
}