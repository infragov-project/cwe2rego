package glitch

import data.glitch_lib

password_pattern = "(?i)(password|passwd|pwd|passphrase|secret|credentials|auth_token|api_key|key)"

empty_value(v) {
    v.ir_type == "String"
    v.value == ""
} else {
    v.ir_type == "Null"
} else {
    v.ir_type == "Undef"
}

contains_sensitive_word(name) {
    regex.match(password_pattern, name)
}

contains_exclusion_term(name) {
    regex.match("(?i).*(cache|proxy|ssl|clientkey|certificate|keyfile|cert).*", name)
}

check_function_arg_empty(node, func_call) {
    func_call.ir_type == "FunctionCall"
    arg := func_call.args[_]
    arg.ir_type == "VariableReference"
    var_name := arg.value
    some ub
    glitch_lib._gather_parent_unit_blocks[ub]
    vars := glitch_lib.all_variables(ub)
    var := vars[_]
    var.name == var_name
    empty_value(var.value)
}

check_code_string_for_empty_var(node, var_name) {
    node.ir_type == "UnitBlock"
    regex.match(sprintf("(?m)\\$%s\\s*=\\s*(''|\"\"|undef|~)", [var_name]), node.code)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    contains_sensitive_word(var.name)
    empty_value(var.value)
    not contains_exclusion_term(var.name)

    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in variable - Using an empty password for sensitive variables can lead to unauthorized access. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    contains_sensitive_word(attr.name)
    empty_value(attr.value)
    not contains_exclusion_term(attr.name)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Using an empty password for sensitive attributes can lead to unauthorized access. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "String"
    attr.value.value != ""
    contains_sensitive_word(attr.name)
    not contains_exclusion_term(attr.name)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Using an empty password for sensitive attributes can lead to unauthorized access. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "FunctionCall"
    func_call := attr.value
    contains_sensitive_word(attr.name)
    not contains_exclusion_term(attr.name)
    
    check_function_arg_empty(node, func_call)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in function call argument - The function call uses a variable that is an empty password. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "FunctionCall"
    func_call := attr.value
    contains_sensitive_word(attr.name)
    not contains_exclusion_term(attr.name)
    
    arg := func_call.args[_]
    arg.ir_type == "VariableReference"
    var_name := arg.value
    check_code_string_for_empty_var(parent, var_name)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in function call argument - The function call uses a variable that is an empty password. (CWE-258)"
    }
}