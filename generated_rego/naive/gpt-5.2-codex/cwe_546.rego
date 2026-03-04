package glitch

import data.glitch_lib

suspicious_terms := {
    "\\bTODO\\b",
    "\\bFIXME\\b",
    "\\bBUG\\b",
    "\\bHACK\\b",
    "\\bXXX\\b",
    "\\bTBD\\b",
    "\\bLATER2?\\b",
    "\\bTEMP(ORARY)?\\b",
    "\\bWORKAROUND\\b",
    "\\bFIX(ES|ED|ING)?\\b",
    "\\bNOT\\s+IMPLEMENTED\\b",
    "\\bNOT\\s+SECURE\\b",
    "\\bNO\\s+AUTH\\b",
    "\\bNO\\s+AUTHENTICATION\\b",
    "disable auth",
    "skip validation",
    "no encryption",
    "open to public",
    "allow all",
    "for testing only",
    "testing only",
    "for test only",
    "test only",
    "remove later",
    "secure later",
    "will secure later",
    "to be restricted",
    "should be private",
    "needs encryption",
    "needs security review",
    "left open for testing",
    "temporary rule",
    "hardcoded",
    "insecure",
    "bypass"
}

annotation_fields := {
    "description",
    "desc",
    "note",
    "notes",
    "annotation",
    "annotations",
    "tag",
    "tags",
    "label",
    "labels",
    "metadata",
    "comment",
    "comments",
    "summary",
    "message",
    "title"
}

suspicious_text(text) {
    term := suspicious_terms[_]
    glitch_lib.contains(text, term)
}

suspicious_comment(c) {
    c.content != ""
    suspicious_text(c.content)
} else {
    c.code != ""
    suspicious_text(c.code)
}

is_annotation_field(name) {
    field := annotation_fields[_]
    glitch_lib.contains(name, field)
}

is_annotation_field(name) {
    regex.match("(?i)^name$", name)
}

comment_in_list(parent, c) {
    c == parent.comments[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    suspicious_comment(comment)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment or annotation indicating temporary or insecure configuration. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent.statements, [_, comment])
    comment.ir_type == "Comment"
    not comment_in_list(parent, comment)
    suspicious_comment(comment)

    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment or annotation indicating temporary or insecure configuration. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_annotation_field(attr.name)
    glitch_lib.traverse(attr.value, suspicious_terms)

    result := {
        "type": "sec_susp_comm",
        "element": attr,
        "path": parent.path,
        "description": "Suspicious comment or annotation indicating temporary or insecure configuration. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    variable := vars[_]
    is_annotation_field(variable.name)
    glitch_lib.traverse(variable.value, suspicious_terms)

    result := {
        "type": "sec_susp_comm",
        "element": variable,
        "path": parent.path,
        "description": "Suspicious comment or annotation indicating temporary or insecure configuration. (CWE-546)"
    }
}