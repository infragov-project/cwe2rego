package glitch

import data.glitch_lib

comment_contains_trigger(content) {
    regex.match(`(?i).*\b(TODO|FIXME|HACK|BUG|INSECURE|XXX|WORKAROUND|TEMP|TEMPORARY|KLUDGE|BODGE|NOTE|DEPRECATED)\b.*`, content)
}

comment_contains_trigger(content) {
    regex.match(`(?i).*(security risk|vulnerable|unsafe|bypass|skip validation|disabled for now|hardcoded|remove before prod|not secure|open to all|fix later|needs review|known issue|will break|cannot change|do not change|broken|deprecated|workaround).*`, content)
}

comment_contains_trigger(content) {
    regex.match(`(?i).*/issues/[0-9].*`, content)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, comment])
    comment.ir_type == "Comment"
    comment_contains_trigger(comment.content)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious or unresolved comment marker detected - Comments indicating unresolved issues, temporary workarounds, or acknowledged security problems should be addressed. (CWE-546)"
    }
}