package glitch

import data.glitch_lib

is_password_name(name) {
    regex.match("(?i).*(password|passwd|pwd|passphrase|activationkey).*", name)
}

is_insecure_value(value) {
    value.ir_type == "String"
    value.value == ""
}

is_insecure_value(value) {
    value.ir_type == "Undef"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_name(attr.name)
    is_insecure_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Using an empty string as a password is insecure. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_password_name(v.name)
    is_insecure_value(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password in configuration file - Using an empty string as a password is insecure. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    empty_param := parent.attributes[_]
    empty_param.value.ir_type == "String"
    empty_param.value.value == ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    au_attrs := glitch_lib.all_attributes(node)
    attr := au_attrs[_]
    is_password_name(attr.name)
    attr.value.ir_type == "FunctionCall"
    arg := attr.value.args[_]
    arg.ir_type == "VariableReference"
    arg.value == empty_param.name
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Using an empty string as a password is insecure. (CWE-258)"
    }
}