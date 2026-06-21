package glitch

import data.glitch_lib

password_pattern := "(?i)(password|passwd|pwd|passphrase|credentials?|auth_pass|db_pass|bind_pass|root_pass|master_pass|activationkey|activation_key)"

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
    var := vars[_]
    regex.match(password_pattern, var.name)
    is_empty_string(var.value)
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration - Password or credential fields should not be assigned empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    regex.match(password_pattern, var.name)
    not regex.match("\\[", var.name)
    is_null_or_undef(var.value)
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration - Password or credential fields should not be assigned empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(password_pattern, attr.name)
    is_empty_string(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password or credential fields should not be assigned empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(password_pattern, attr.name)
    is_null_or_undef(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password or credential fields should not be assigned empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(password_pattern, attr.name)
    attr.value.ir_type == "FunctionCall"
    arg := attr.value.args[_]
    arg.ir_type == "VariableReference"
    empty_var_pattern := sprintf("(?i)\\$%v\\s*=\\s*['\"]['\"]", [arg.value])
    regex.match(empty_var_pattern, parent.code)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Password or credential fields should not be assigned empty or null values. (CWE-258)"
    }
}