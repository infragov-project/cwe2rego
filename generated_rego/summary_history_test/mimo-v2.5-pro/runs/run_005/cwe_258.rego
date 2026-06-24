package glitch

import data.glitch_lib

password_keywords := {"password", "passwd", "pwd", "secret", "credential", "token", "key"}

has_password_keyword(name) {
    keyword := password_keywords[_]
    glitch_lib.contains(name, keyword)
}

is_empty_value(value) {
    value.ir_type == "String"
    trim(value.value, " \t\n\r") == ""
}

is_empty_value(value) {
    value.ir_type == "Null"
}

is_empty_value(value) {
    value.ir_type == "Undef"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    has_password_keyword(var.name)
    is_empty_value(var.value)

    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    has_password_keyword(attr.name)
    is_empty_value(attr.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty. (CWE-258)"
    }
}