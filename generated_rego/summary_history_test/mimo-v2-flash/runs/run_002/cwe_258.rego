package glitch

import data.glitch_lib

sensitive_pattern := `(?i)(password|pwd|passwd|passphrase|credential|auth|token|secret|key)`

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

is_password_related_name(name) {
    regex.match(sensitive_pattern, name)
    not contains(lower(name), "api_token")
    not contains(lower(name), "cache")
    not contains(lower(name), "proxy_password")
    not contains(lower(name), "sslclientkey")
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    
    attr.name != ""
    is_password_related_name(attr.name)
    is_empty_value(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Avoid using empty passwords in authentication configurations. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_vars := glitch_lib.all_variables(parent)
    var := all_vars[_]
    
    var.name != ""
    is_password_related_name(var.name)
    is_empty_value(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in variable assignment - Avoid using empty passwords in authentication configurations. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_function_calls := {n |
        walk(parent, [path, n])
        n.ir_type == "FunctionCall"
    }
    func := all_function_calls[_]
    
    regex.match(sensitive_pattern, func.name)
    
    count(func.args) > 0
    arg := func.args[_]
    
    arg.ir_type == "VariableReference"
    var_name := arg.value
    
    var_def := {n |
        walk(parent, [path, n])
        n.ir_type == "Variable"
        n.name == var_name
    }[_]
    
    is_empty_value(var_def.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var_def,
        "path": parent.path,
        "description": "Empty password used in function call - Avoid using empty passwords in authentication configurations. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_function_calls := {n |
        walk(parent, [path, n])
        n.ir_type == "FunctionCall"
    }
    func := all_function_calls[_]
    
    regex.match(sensitive_pattern, func.name)
    
    count(func.args) > 0
    arg := func.args[_]
    
    arg.ir_type == "String"
    arg.value == ""
    
    result := {
        "type": "sec_empty_pass",
        "element": func,
        "path": parent.path,
        "description": "Empty password used in function call - Avoid using empty passwords in authentication configurations. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    parent.type == "definition"
    
    all_function_calls := {n |
        walk(parent, [path, n])
        n.ir_type == "FunctionCall"
    }
    func := all_function_calls[_]
    
    regex.match(sensitive_pattern, func.name)
    
    count(func.args) > 0
    arg := func.args[_]
    
    arg.ir_type == "VariableReference"
    var_name := arg.value
    
    class_code := parent.code
    regex.match(sprintf(`\$\s*%s\s*=\s*(''|")`, [var_name]), class_code)
    
    result := {
        "type": "sec_empty_pass",
        "element": func,
        "path": parent.path,
        "description": "Empty password used in function call (class parameter) - Avoid using empty passwords in authentication configurations. (CWE-258)"
    }
}