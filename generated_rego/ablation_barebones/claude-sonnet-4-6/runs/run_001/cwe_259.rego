package glitch

import data.glitch_lib

is_password_name(name) {
    regex.match("(?i).*(password|passwd|pwd|pass|secret|credential).*", name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    is_password_name(attr.name)
    attr.value.ir_type == "String"
    attr.value.value != ""

    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - A hard-coded password was detected in an attribute. Passwords should not be stored in plain text within IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]

    is_password_name(v.name)
    v.value.ir_type == "String"
    v.value.value != ""

    result := {
        "type": "sec_hard_pass",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded password - A hard-coded password was detected in a variable. Passwords should not be stored in plain text within IaC scripts. (CWE-259)"
    }
}