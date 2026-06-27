package glitch

import data.glitch_lib

credential_keywords := {"password", "passwd", "pwd", "secret", "credential", "auth_token", "api_key", "access_key", "private_key", "token", "admin_password", "master_password", "root_password", "console_password", "mgmt_password", "client_secret", "keystore_password", "truststore_password", "key", "auth"}

has_credential_keyword(name) {
    lower_name := lower(name)
    kw := credential_keywords[_]
    contains(lower_name, kw)
}

is_string_literal(x) {
    x.ir_type == "String"
    count(x.value) > 0
}

contains_safe_reference(node) {
    walk(node)[_][n]
    n.ir_type == "VariableReference"
}

contains_function_call(node) {
    walk(node)[_][n]
    n.ir_type == "FunctionCall"
}

is_env_var_reference(value) {
    contains(value, "{{")
    contains(value, "}}")
}

is_file_path(value) {
    regex.match("^(file|ftp|http|https|ssh|git)://", value)
}

is_hash_prefix(value) {
    regex.match("^\\$[0-9a-zA-Z]+\\$", value)
}

is_placeholder(value) {
    lower_val := lower(value)
    lower_val == ""
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent)[_][node]
    
    node.ir_type == "Hash"
    entry := node.value[_]
    
    entry.key.ir_type == "String"
    val := entry.value
    
    has_credential_keyword(entry.key.value)
    is_string_literal(val)
    
    not contains_safe_reference(val)
    not contains_function_call(val)
    not is_file_path(val.value)
    not is_hash_prefix(val.value)
    not is_placeholder(val.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": val,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be stored directly in code. Use environment variables, secret managers, or variable references. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent)[_][var]
    
    var.ir_type == "Variable"
    val := var.value
    
    has_credential_keyword(var.name)
    is_string_literal(val)
    
    not contains_safe_reference(val)
    not contains_function_call(val)
    not is_file_path(val.value)
    not is_hash_prefix(val.value)
    not is_placeholder(val.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be stored directly in code. Use environment variables, secret managers, or variable references. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent)[_][attr]
    
    attr.ir_type == "Attribute"
    val := attr.value
    
    has_credential_keyword(attr.name)
    is_string_literal(val)
    
    not contains_safe_reference(val)
    not contains_function_call(val)
    not is_file_path(val.value)
    not is_hash_prefix(val.value)
    not is_placeholder(val.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be stored directly in code. Use environment variables, secret managers, or variable references. (CWE-259)"
    }
}