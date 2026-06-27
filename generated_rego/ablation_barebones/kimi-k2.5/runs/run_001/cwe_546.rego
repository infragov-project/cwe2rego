package glitch

import data.glitch_lib

suspicious_patterns := {"BUG", "HACK", "FIXME", "LATER", "LATER2", "TODO"}

contains_suspicious(content) {
    pattern := suspicious_patterns[_]
    regex.match(sprintf("(?i)\\b%s\\b", [pattern]), content)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    contains_suspicious(comment.content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious Comment - The code contains comments that suggest the presence of bugs, incomplete functionality, or weaknesses. (CWE-546)"
    }
}