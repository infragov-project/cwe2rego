package glitch

import data.glitch_lib

is_password_key(name) {
    regex.match("(?i).*(password|passwd|pwd|secret|credential|token).*", name)
}

is_password_key(name) {
    lower(name) == "key"
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    is_password_key(attr.name)
    is_hardcoded_string(attr.value)
    glitch_lib.traverse_var(attr.value)

    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords should not be hard-coded in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    is_password_key(var.name)
    is_hardcoded_string(var.value)
    glitch_lib.traverse_var(var.value)

    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords should not be hard-coded in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, entry])
    entry.key.ir_type == "String"
    is_password_key(entry.key.value)
    is_hardcoded_string(entry.value)
    glitch_lib.traverse_var(entry.value)

    result := {
        "type": "sec_hard_pass",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords should not be hard-coded in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match("(?i).*(password|passwd|pwd|secret|credential|token).*=.+", node.value)

    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords should not be hard-coded in IaC scripts. (CWE-259)"
    }
}