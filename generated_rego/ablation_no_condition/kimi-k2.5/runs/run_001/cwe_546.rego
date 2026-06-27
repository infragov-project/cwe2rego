package glitch

import data.glitch_lib

suspicious_patterns := {
    "BUG", "HACK", "FIXME", "TODO", "LATER", "LATER2", "XXX",
    "/issues/", "issues/", "github.com/.*/issues/",
    "break", "broken", "deprecat", "incomplete", "workaround",
    "temporary", "temp", "broken", "will break", "cannot change"
}

check_comment_content(content) {
    pattern := suspicious_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), content)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    check_comment_content(comment.content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious Comment - The code contains comments that suggest the presence of bugs, incomplete functionality, or weaknesses. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, node])
    node.ir_type == "Comment"
    check_comment_content(node.content)

    result := {
        "type": "sec_susp_comm",
        "element": node,
        "path": "",
        "description": "Suspicious Comment - The code contains comments that suggest the presence of bugs, incomplete functionality, or weaknesses. (CWE-546)"
    }
}