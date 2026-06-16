package glitch

import data.glitch_lib

password_keywords := {"password", "passwd", "admin_password", "db_password", "proxy_password", "auth_token", "api_key", "activationkey", "ssh_password"}
connection_string_patterns := {"pwd=;", "password=;", ";password="}

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
}

is_password_variable(name) {
    keyword := password_keywords[_]
    glitch_lib.contains(name, keyword)
}

is_empty_expr(expr, parent_unit) {
    is_empty_value(expr)
} else {
    expr.ir_type == "VariableReference"
    var_name := expr.value
    vars := glitch_lib.all_variables(parent_unit)
    var := vars[_]
    var.name == var_name
    is_empty_value(var.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_password_variable(var.name)
    is_empty_value(var.value)
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - Passwords should not be set to empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    is_password_variable(attr.name)
    is_empty_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Passwords should not be set to empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := parent.attributes[_]
    is_password_variable(attr.name)
    is_empty_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Passwords should not be set to empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    string_value := var.value.value
    pattern := connection_string_patterns[_]
    regex.match(pattern, string_value)
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in connection string - Connection string contains an empty password. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    attr.value.ir_type == "String"
    string_value := attr.value.value
    pattern := connection_string_patterns[_]
    regex.match(pattern, string_value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in connection string - Connection string contains an empty password. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    attr.value.ir_type == "FunctionCall"
    func_call := attr.value
    is_password_variable(attr.name)
    count(func_call.args) > 0
    some arg
    arg = func_call.args[_]
    is_empty_expr(arg, parent)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration function - Function call uses empty password value. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(unit)
    attr := attrs[_]
    attr.value.ir_type == "FunctionCall"
    func_call := attr.value
    is_password_variable(func_call.name)
    count(func_call.args) > 0
    some arg
    arg = func_call.args[_]
    is_empty_expr(arg, parent)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration function - Function call uses empty password value. (CWE-258)"
    }
}