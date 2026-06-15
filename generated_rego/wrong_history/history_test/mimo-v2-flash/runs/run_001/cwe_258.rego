package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    password_field_names := {"password", "pwd", "pass", "secret", "key", "token", "credential", "auth"}
    contains_password := regex.match(sprintf("(?i).*(%s).*", [concat("|", password_field_names)]), var.name)

    empty_password := var.value.ir_type == "String" and var.value.value == ""
    null_password := var.value.ir_type == "Null"

    contains_password
    (empty_password or null_password)

    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields must not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    password_field_names := {"password", "pwd", "pass", "secret", "key", "token", "credential", "auth"}
    contains_password := regex.match(sprintf("(?i).*(%s).*", [concat("|", password_field_names)]), attr.name)

    empty_password := attr.value.ir_type == "String" and attr.value.value == ""
    null_password := attr.value.ir_type == "Null"

    contains_password
    (empty_password or null_password)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields must not be empty or null. (CWE-258)"
    }
}