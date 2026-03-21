package glitch

import data.glitch_lib

base_password_pattern := "(?i).*(password|passwd|pwd|pass|secret|credential).*"
secret_key_exclusion := "(?i).*secret.?key.*"
activation_key_pattern := "(?i).*activat.*key.*"
permissive_flag_pattern := "(?i).*(allow_empty_password|no_password|skip_password|disable_password_auth).*"
proxy_exclusion := "(?i).*(proxy).*(password|passwd|pwd|pass)|(password|passwd|pwd|pass).*(proxy).*"

is_password_field(name) {
    regex.match(base_password_pattern, name)
    not regex.match(secret_key_exclusion, name)
}

is_password_field(name) {
    regex.match(activation_key_pattern, name)
}

is_empty_string(value) {
    value.ir_type == "String"
    trim_space(value.value) == ""
}

is_absent_value(value) {
    value.ir_type == "Null"
}

is_absent_value(value) {
    value.ir_type == "Undef"
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
        "description": "Empty password in configuration - Password-related field should not have an empty value. (CWE-258)"
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
        "description": "Empty password in configuration - Password-related field should not have an empty value. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_password_field(v.name)
    is_absent_value(v.value)
    not regex.match(proxy_exclusion, v.name)
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Absent password in configuration - Password-related field should not be null or undefined. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field(attr.name)
    is_absent_value(attr.value)
    not regex.match(proxy_exclusion, attr.name)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Absent password in configuration - Password-related field should not be null or undefined. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    password_attr := attrs[_]
    is_password_field(password_attr.name)
    password_attr.value.ir_type == "FunctionCall"
    arg := password_attr.value.args[_]
    arg.ir_type == "VariableReference"
    ref_attr := attrs[_]
    ref_attr.name == arg.value
    is_empty_string(ref_attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": password_attr,
        "path": parent.path,
        "description": "Password-related field calls a function with an empty password variable. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    password_attr := attrs[_]
    is_password_field(password_attr.name)
    password_attr.value.ir_type == "FunctionCall"
    arg := password_attr.value.args[_]
    arg.ir_type == "VariableReference"
    vars := glitch_lib.all_variables(parent)
    ref_var := vars[_]
    ref_var.name == arg.value
    is_empty_string(ref_var.value)
    result := {
        "type": "sec_empty_pass",
        "element": password_attr,
        "path": parent.path,
        "description": "Password-related field calls a function with an empty password variable. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(permissive_flag_pattern, attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Configuration allows empty passwords through a permissive flag. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(permissive_flag_pattern, v.name)
    v.value.ir_type == "Boolean"
    v.value.value == true
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Configuration allows empty passwords through a permissive flag. (CWE-258)"
    }
}