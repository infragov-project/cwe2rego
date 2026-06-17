package glitch

import data.glitch_lib
import future.keywords.in

password_keywords := {"password", "pwd", "passphrase", "secret", "credential", "api_key", "token", "auth_key", "key"}

check_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

name_contains_password_keyword(name) {
    some keyword in password_keywords
    glitch_lib.contains(lower(name), keyword)
}

is_false_positive(name) {
    glitch_lib.contains(name, "proxy_password")
} else {
    glitch_lib.contains(name, "sslclientkey")
} else {
    glitch_lib.contains(name, "api_token")
} else {
    glitch_lib.contains(name, "access_key")
} else {
    glitch_lib.contains(name, "secret_key")
}

resolve_variable_value(var_ref, current_block) = value {
    var_ref.ir_type == "VariableReference"
    var_name := var_ref.value
    current_block.variables[_].name == var_name
    value := current_block.variables[_].value
} else {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.variables[_].name == var_ref.value
    value := parent.variables[_].value
} else {
    var_ref.ir_type == "VariableReference"
    var_name := var_ref.value
    all_vars := glitch_lib.all_variables(input)
    some v in all_vars
    v.name == var_name
    value := v.value
}

is_empty_password_argument(arg, unit_block) {
    check_empty_value(arg)
} else {
    arg.ir_type == "VariableReference"
    resolved := resolve_variable_value(arg, unit_block)
    check_empty_value(resolved)
}

Glitch_Analysis[result] {
    unit_block := glitch_lib._gather_parent_unit_blocks[_]
    unit_block.path != ""
    
    var := unit_block.variables[_]
    name_contains_password_keyword(var.name)
    not is_false_positive(var.name)
    check_empty_value(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": unit_block.path,
        "description": "Empty password in configuration file - Password variables should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    unit_block := glitch_lib._gather_parent_unit_blocks[_]
    unit_block.path != ""
    
    attr := unit_block.attributes[_]
    name_contains_password_keyword(attr.name)
    not is_false_positive(attr.name)
    check_empty_value(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": unit_block.path,
        "description": "Empty password in configuration file - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    all_units := glitch_lib.all_atomic_units(input)
    unit := all_units[_]
    
    var := unit.variables[_]
    name_contains_password_keyword(var.name)
    not is_false_positive(var.name)
    check_empty_value(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": unit.path,
        "description": "Empty password in configuration file - Password variables should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    all_units := glitch_lib.all_atomic_units(input)
    unit := all_units[_]
    
    attr := unit.attributes[_]
    name_contains_password_keyword(attr.name)
    not is_false_positive(attr.name)
    check_empty_value(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": unit.path,
        "description": "Empty password in configuration file - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    unit_block := glitch_lib._gather_parent_unit_blocks[_]
    unit_block.path != ""
    
    walk(unit_block, [_, node])
    node.ir_type == "FunctionCall"
    
    name_contains_password_keyword(node.name)
    
    some arg in node.args
    is_empty_password_argument(arg, unit_block)
    
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": unit_block.path,
        "description": "Empty password used in function call - Password arguments should not be empty. (CWE-258)"
    }
}