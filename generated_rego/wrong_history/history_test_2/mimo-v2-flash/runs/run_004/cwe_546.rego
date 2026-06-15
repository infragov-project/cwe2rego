package glitch

import data.glitch_lib

suspicious_pattern = "(?i)todo|fixme|bug|hack|later|later2|xxx|temp|workaround|insecure|do not use in prod|hardcoded|debug|testing only|change_me|replace_me"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match(suspicious_pattern, attr.value.value)
    result := {
        "type": "sec_susp_comm",
        "element": attr,
        "path": parent.path,
        "description": "Suspicious comment or placeholder found in attribute value. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    regex.match(suspicious_pattern, var.value.value)
    result := {
        "type": "sec_susp_comm",
        "element": var,
        "path": parent.path,
        "description": "Suspicious comment or placeholder found in variable value. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    comment := parent.comments[_]
    regex.match(suspicious_pattern, comment.content)
    result := {
        "type": "sec_susp_comm",
        "element": comment,
        "path": parent.path,
        "description": "Suspicious comment found. (CWE-546)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    atom := atomic_units[_]
    atom.name.ir_type == "String"
    regex.match(suspicious_pattern, atom.name.value)
    result := {
        "type": "sec_susp_comm",
        "element": atom,
        "path": parent.path,
        "description": "Suspicious keyword in resource name. (CWE-546)"
    }
}