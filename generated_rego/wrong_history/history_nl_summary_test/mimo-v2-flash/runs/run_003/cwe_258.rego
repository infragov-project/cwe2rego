package glitch

import data.glitch_lib

password_keywords := {"password", "pwd", "pass", "secret", "key", "token", "credential", "auth", "secret_key", "api_key", "db_password", "admin_password"}

check_empty_password(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

is_password_variable(name) {
    pattern := concat("|", password_keywords)
    full_pattern := concat("", ["(?i)(", pattern, ")"])
    regex.match(full_pattern, name)
    not regex.match("(?i)gitlab_runner__.*token", name)
    not regex.match("(?i)proxy_password", name)
    not regex.match("(?i)sslclientkey", name)
    not regex.match("(?i)cache.*key", name)
}

check_hash_for_empty_password(hash_value) {
    hash_value.ir_type == "Hash"
    some key
    val := hash_value.value[key]
    key.ir_type == "String"
    is_password_variable(key.value)
    check_empty_password(val)
}

check_variable_empty_password(var_node) {
    var_node.ir_type == "Variable"
    is_password_variable(var_node.name)
    check_empty_password(var_node.value)
}

check_attribute_empty_password(attr_node) {
    attr_node.ir_type == "Attribute"
    is_password_variable(attr_node.name)
    check_empty_password(attr_node.value)
}

check_function_call_empty_password(func_node) {
    func_node.ir_type == "FunctionCall"
    pattern := concat("|", password_keywords)
    full_pattern := concat("", ["(?i)(", pattern, ")"])
    regex.match(full_pattern, func_node.name)
    count(func_node.args) > 0
    arg := func_node.args[0]
    check_empty_password(arg)
}

check_function_call_variable_empty_password(func_node, parent) {
    func_node.ir_type == "FunctionCall"
    pattern := concat("|", password_keywords)
    full_pattern := concat("", ["(?i)(", pattern, ")"])
    regex.match(full_pattern, func_node.name)
    count(func_node.args) > 0
    arg := func_node.args[0]
    arg.ir_type == "VariableReference"
    var_name := arg.value
    is_password_variable(var_name)
    some var_node
    walk(parent, [_, var_node])
    var_node.ir_type == "Variable"
    var_node.name == var_name
    check_empty_password(var_node.value)
}

check_function_call_variable_empty_password(func_node, parent) {
    func_node.ir_type == "FunctionCall"
    pattern := concat("|", password_keywords)
    full_pattern := concat("", ["(?i)(", pattern, ")"])
    regex.match(full_pattern, func_node.name)
    count(func_node.args) > 0
    arg := func_node.args[0]
    arg.ir_type == "VariableReference"
    var_name := arg.value
    is_password_variable(var_name)
    parent_code := parent.code
    regex.match(sprintf("(?i)\\$%s\\s*=\\s*['\"]\\s*['\"]", [var_name]), parent_code)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    check_variable_empty_password(node)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    check_attribute_empty_password(node)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    value := node.value
    check_hash_for_empty_password(value)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    check_function_call_empty_password(node)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    check_function_call_variable_empty_password(node, parent)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - (CWE-258)"
    }
}