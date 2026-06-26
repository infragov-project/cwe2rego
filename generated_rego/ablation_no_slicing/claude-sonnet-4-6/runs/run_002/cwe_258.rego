package glitch

import data.glitch_lib

is_password_field(name) {
    regex.match("(?i).*(password|passwd|pwd|secret|credential|auth_pass|bind_pass|activationkey|activation_key).*", name)
    not regex.match("(?i).*(secret_key|secretkey).*", name)
}

is_strict_password_field(name) {
    regex.match("(?i)^(password|passwd|pwd|secret|credential)$", name)
}

is_strict_password_field(name) {
    regex.match("(?i).*\\[['\"](password|passwd|pwd|secret|credential)['\"]\\]\\s*$", name)
}

is_empty_string(value) {
    value.ir_type == "String"
    value.value == ""
}

is_null_or_undef(value) {
    value.ir_type == "Null"
}

is_null_or_undef(value) {
    value.ir_type == "Undef"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    variable := vars[_]
    is_password_field(variable.name)
    is_empty_string(variable.value)
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not have empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    variable := vars[_]
    is_strict_password_field(variable.name)
    is_null_or_undef(variable.value)
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not have empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field(attr.name)
    is_empty_string(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not have empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field(attr.name)
    is_null_or_undef(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not have empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field(attr.name)
    attr.value.ir_type == "FunctionCall"
    arg := attr.value.args[_]
    arg.ir_type == "VariableReference"
    var_name := arg.value
    scope_attrs := glitch_lib.all_attributes(parent)
    defining := scope_attrs[_]
    defining.name == var_name
    is_empty_string(defining.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not have empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field(attr.name)
    attr.value.ir_type == "FunctionCall"
    arg := attr.value.args[_]
    arg.ir_type == "VariableReference"
    var_name := arg.value
    scope_vars := glitch_lib.all_variables(parent)
    defining := scope_vars[_]
    defining.name == var_name
    is_empty_string(defining.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password fields should not have empty values. (CWE-258)"
    }
}