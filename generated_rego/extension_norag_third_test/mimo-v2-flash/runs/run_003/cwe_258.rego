package glitch

import future.keywords.in
import data.glitch_lib

password_keywords := {"password", "pwd", "passwd", "secret", "key", "token", "activationkey", "auth", "credentials", "credential"}

is_password_field(name) {
    name_lower := lower(name)
    some keyword in password_keywords
    contains(name_lower, keyword)
}

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "String"
    regex.match("^\\s*$", value.value)
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_password_field(var.name)
    is_empty_value(var.value)
    not glitch_lib.has_variable_reference(var.value)
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password or secret in configuration file - Secrets should not be set to empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_password_field(attr.name)
    is_empty_value(attr.value)
    not glitch_lib.has_variable_reference(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password or secret in configuration file - Secrets should not be set to empty values. (CWE-258)"
    }
}