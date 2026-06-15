package glitch

import data.glitch_lib

password_keywords := {"password", "pwd", "secret", "key", "admin_password", "db_password", "secret_key", "authentication", "connection_string"}

empty_string(value) {
    value.ir_type == "String"
    regex.match("^\\s*$", value.value)
}

contains_password_keyword(str) {
    some keyword
    password_keywords[keyword]
    regex.match(sprintf("(?i).*%s.*", [keyword]), str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    some attr
    attrs[attr]
    contains_password_keyword(attr.name)
    empty_string(attr.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password assigned to a password-related attribute. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    vars := glitch_lib.all_variables(node)
    some var
    vars[var]
    contains_password_keyword(var.name)
    empty_string(var.value)

    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password assigned to a password-related variable. (CWE-258)"
    }
}