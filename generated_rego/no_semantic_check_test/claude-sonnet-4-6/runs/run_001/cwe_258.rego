package glitch

import data.glitch_lib

is_password_field(name) {
    regex.match("(?i).*(password|passwd|pwd|passphrase|secret_key|token_secret|api_secret|bind_pass|sa_pass).*", name)
}

is_empty_value(value) {
    value.ir_type == "String"
    regex.match("^\\s*$", value.value)
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
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    is_password_field(attr.name)
    is_empty_value(attr.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be assigned empty or null values, as this may bypass authentication. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    is_password_field(var.name)
    is_empty_value(var.value)

    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - Password variables should not be assigned empty or null values, as this may bypass authentication. (CWE-258)"
    }
}