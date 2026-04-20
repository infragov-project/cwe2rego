package glitch

import data.glitch_lib

password_keywords := {"password", "pwd", "passwd", "secret", "token", "credential"}

check_empty_password(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

check_empty_password_connection_string(str) {
    regex.match(`(?i)(password|pwd|secret|token)=[\s]*([;&\s]|$)`, str)
}

is_password_context(name) {
    keyword := password_keywords[_]
    contains(lower(name), keyword)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    is_password_context(var.name)
    check_empty_password(var.value)
    not contains(lower(var.name), "cache")
    not contains(lower(var.name), "api")
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Variable with empty password-related value (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    is_password_context(attr.name)
    check_empty_password(attr.value)
    not contains(lower(attr.name), "cache")
    not contains(lower(attr.name), "api")
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Attribute with empty password-related value (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    check_empty_password_connection_string(node.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Connection string with empty password field (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    is_password_context(node.name)
    arg := node.args[_]
    arg.ir_type == "VariableReference"
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.name == arg.value
    check_empty_password(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Function using empty password variable (CWE-258)"
    }
}