package glitch

import data.glitch_lib

password_patterns := {"password", "passwd", "pwd", "secret", "credentials", "auth_token", "api_key", "access_key", "private_key", "secret_key", "service_account_key", "initial_password", "bootstrap_password", "setup_credential", "master_password", "replication_password", "root_password", "vpn_psk", "ipsec_secret", "certificate_password", "image_pull_secret", "registry_password", "sha512_password"}

weak_passwords := {"password", "123456", "123456789", "qwerty", "password123", "admin", "letmein", "welcome", "monkey", "12345678", "abc123", "football", "iloveyou", "admin123", "welcome123", "password1", "123123", "987654321", "qwertyuiop", "password123!", "changeme", "default", "root", "root123", "passw0rd", "test", "temp", "telarista", "some_password", "pass", "pass123"}

is_password_key(key) {
    lower_key := lower(key)
    pattern := password_patterns[_]
    contains_str(lower_key, pattern)
}

contains_str(str, substr) {
    regex.match(sprintf(".*%s.*", [substr]), str)
}

is_weak_password(str) {
    lower_str := lower(str)
    weak := weak_passwords[_]
    lower_str == weak
}

is_hashed_password(str) {
    regex.match("^\\$[0-9a-zA-Z]+\\$", str)
}

is_safe_value(val) {
    val.ir_type == "String"
    contains_secret_ref(val.value)
}

contains_secret_ref(str) {
    regex.match("\\$\\{.*\\}", str)
} else {
    regex.match("\\{\\{.*\\}\\}", str)
} else {
    regex.match("(?i)(lookup|vault|secret|data|var|module|local)\\s*\\(", str)
} else {
    regex.match("(?i)(data\\.terraform_remote_state|aws_secretsmanager|azurerm_key_vault)", str)
}

has_variable_reference(node) {
    walk(node, [_, n])
    n.ir_type == "VariableReference"
}

has_function_call(node) {
    walk(node, [_, n])
    n.ir_type == "FunctionCall"
}

is_hardcoded_string(val) {
    val.ir_type == "String"
    count(val.value) > 0
    not is_safe_value(val)
    not has_variable_reference(val)
    not has_function_call(val)
}

check_value_for_password(val, key) {
    is_password_key(key)
    val.ir_type == "String"
    is_hardcoded_string(val)
    not is_hashed_password(val.value)
}

get_element_info(val, key) = result {
    result := {
        "ir_type": "Attribute",
        "name": key,
        "value": val,
        "line": val.line,
        "column": val.column,
        "end_line": val.end_line,
        "end_column": val.end_column,
        "code": val.code
    }
}

# Check for password patterns in nested hash structures
check_hash_entry(hash, key, val) {
    is_password_key(key)
    check_value_for_password(val, key)
}

# Recursively check all hash structures for password patterns
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    # Handle Hash type
    node.ir_type == "Hash"
    
    entry := node.value[_]
    entry.key.ir_type == "String"
    key := entry.key.value
    val := entry.value
    
    check_hash_entry(hash, key, val)
    
    result := {
        "type": "sec_hard_pass",
        "element": get_element_info(val, key),
        "path": parent.path,
        "description": "Use of Hard-coded Password - Credentials should not be hardcoded in configuration files. Use secure secret management instead. (CWE-259)"
    }
}

# Check Variables at the top level
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    node := parent.variables[_]
    is_password_key(node.name)
    check_value_for_password(node.value, node.name)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Credentials should not be hardcoded in configuration files. Use secure secret management instead. (CWE-259)"
    }
}

# Check Attributes in AtomicUnits
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    au := parent.atomic_units[_]
    a := au.attributes[_]
    is_password_key(a.name)
    check_value_for_password(a.value, a.name)
    
    result := {
        "type": "sec_hard_pass",
        "element": a,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Credentials should not be hardcoded in configuration files. Use secure secret management instead. (CWE-259)"
    }
}

# Check nested UnitBlocks recursively
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Recursively check nested unit blocks
    check_nested_unit_blocks(parent, result)
}

check_nested_unit_blocks(node, result) {
    ub := node.unit_blocks[_]
    walk(ub, [_, inner_node])
    
    # Check Variables in nested blocks
    inner_node.ir_type == "Variable"
    is_password_key(inner_node.name)
    check_value_for_password(inner_node.value, inner_node.name)
    
    result := {
        "type": "sec_hard_pass",
        "element": inner_node,
        "path": ub.path,
        "description": "Use of Hard-coded Password - Credentials should not be hardcoded in configuration files. Use secure secret management instead. (CWE-259)"
    }
}

check_nested_unit_blocks(node, result) {
    ub := node.unit_blocks[_]
    walk(ub, [_, inner_node])
    
    # Check Hash entries in nested blocks
    inner_node.ir_type == "Hash"
    
    entry := inner_node.value[_]
    entry.key.ir_type == "String"
    key := entry.key.value
    val := entry.value
    
    check_hash_entry(inner_node, key, val)
    
    result := {
        "type": "sec_hard_pass",
        "element": get_element_info(val, key),
        "path": ub.path,
        "description": "Use of Hard-coded Password - Credentials should not be hardcoded in configuration files. Use secure secret management instead. (CWE-259)"
    }
}