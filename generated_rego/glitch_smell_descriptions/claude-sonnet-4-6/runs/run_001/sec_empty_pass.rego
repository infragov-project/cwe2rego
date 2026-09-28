package glitch

import data.glitch_lib

is_password_field(name) {
    regex.match("(?i)(^|[_\\[\\]'\"./-])(password|passwd|pwd|pass|credentials|auth_pass|db_password|master_password|login_password|account_password|access_password|auth_password|admin_password|root_password|user_password|activationkey)([_\\[\\]'\"./-]|$)", name)
    not regex.match("(?i)(^|[_\\[\\]'\"./-])proxy[_\\[\\]'\"./-]", name)
}

is_empty_string(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty_string(value) {
    value.ir_type == "String"
    regex.match("^\\s+$", value.value)
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
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field(attr.name)
    is_empty_string(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password detected - Password fields should not be set to empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_password_field(v.name)
    is_empty_string(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password detected - Password fields should not be set to empty or null values. (CWE-258)"
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
        "description": "Empty password detected - Password fields should not be set to empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_password_field(v.name)
    is_null_or_undef(v.value)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty password detected - Password fields should not be set to empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    inner_ub := parent.unit_blocks[_]
    inner_ub.path != ""
    attrs := glitch_lib.all_attributes(inner_ub)
    attr := attrs[_]
    is_password_field(attr.name)
    attr.value.ir_type == "FunctionCall"
    arg := attr.value.args[_]
    arg.ir_type == "VariableReference"
    var_name := arg.value
    param := inner_ub.attributes[_]
    param.name == var_name
    is_empty_string(param.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": inner_ub.path,
        "description": "Empty password detected - Password fields should not be set to empty or null values. (CWE-258)"
    }
}