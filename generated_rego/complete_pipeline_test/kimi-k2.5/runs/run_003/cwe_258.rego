package glitch

import data.glitch_lib
import future.keywords.in

password_keywords := {"password", "passwd", "pwd", "secret", "secretkey", "secret_key", "access_key_secret", "credentials", "auth_token", "api_key", "admin_password", "root_password", "master_password", "user_password", "activationkey", "pass", "auth"}

is_password_key(name) {
    lower_name := lower(name)
    not contains(lower_name, "public")
    not contains(lower_name, "public_key")
    not contains(lower_name, "secret_key_base")
    not contains(lower_name, "secret_key")
    not contains(lower_name, "cache_secret")
    not contains(lower_name, "proxy_")
    kw := password_keywords[_]
    contains(lower_name, kw)
}

is_empty_or_null(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty_or_null(value) {
    value.ir_type == "Null"
}

is_empty_or_null(value) {
    value.ir_type == "Undef"
}

has_empty_in_structure(value) {
    is_empty_or_null(value)
}

has_empty_in_structure(value) {
    walk(value, [_, node])
    node != value
    is_empty_or_null(node)
}

find_variable_in_scope(var_name, scope) = value {
    walk(scope, [_, candidate])
    candidate.ir_type in {"Variable", "Attribute"}
    candidate.name == var_name
    value := candidate.value
}

resolve_args_point_to_empty(args, scope) {
    arg := args[_]
    arg.ir_type == "VariableReference"
    resolved := find_variable_in_scope(arg.value, scope)
    is_empty_or_null(resolved)
}

resolve_args_point_to_empty(args, scope) {
    arg := args[_]
    has_empty_in_structure(arg)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walked = [node | walk(parent, [_, node])]
    node := walked[_]
    
    node.ir_type in {"Variable", "Attribute"}
    is_password_key(node.name)
    is_empty_or_null(node.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walked = [node | walk(parent, [_, node])]
    node := walked[_]
    
    node.ir_type == "Attribute"
    is_password_key(node.name)
    node.value.ir_type == "FunctionCall"
    
    resolve_args_point_to_empty(node.value.args, parent)
    
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty or null. (CWE-258)"
    }
}