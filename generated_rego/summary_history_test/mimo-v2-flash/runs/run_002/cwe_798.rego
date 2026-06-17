package glitch

import data.glitch_lib
import future.keywords.in

sensitive_keys := {
    "password", "secret", "key", "token", "api_key", "secret_key", "access_key", 
    "private_key", "secret_value", "admin_password", "db_password", "encryption_key", 
    "signing_key", "ssh_private_key", "auth_token", "bearer_token", "shared_secret", 
    "connection_string", "db_url", "username", "endpoint_credentials", 
    "deploy_token", "ci_cd_secret", "webhook_secret", "github_token", "sha512_password",
    "keystore_password", "truststore_password", "rbd_secret_uuid"
}

default_values := {
    "admin", "password", "root", "123456", "12345678", "123456789", "12345", "1234", "123", "12", "1", 
    "letmein", "welcome", "monkey", "qwerty", "abc123", "password1", "passw0rd", "zaq12wsx"
}

is_default_value(str) {
    lower_str := lower(str)
    default_values[_] == lower_str
}

is_hardcoded_literal(node) {
    not glitch_lib.has_variable_reference(node)
}

is_hardcoded_string(node) {
    node.ir_type == "String"
    is_hardcoded_literal(node)
    not is_default_value(node.value)
}

is_default_string(node) {
    node.ir_type == "String"
    is_hardcoded_literal(node)
    is_default_value(node.value)
}

is_sensitive_key(key) {
    lower_key := lower(key)
    sensitive_keys[_] == lower_key
}

extract_key_name(key) = part {
    cleaned := trim_prefix(key, "$")
    parts := split(cleaned, "[")
    last_bracket := parts[count(parts)-1]
    no_close_bracket := replace(last_bracket, "]", "")
    no_quotes := replace(replace(no_close_bracket, "'", ""), "\"", "")
    dot_parts := split(no_quotes, ".")
    last_dot := dot_parts[count(dot_parts)-1]
    part := last_dot
}

is_sensitive_key_pattern(key) {
    lower_key := lower(key)
    is_sensitive_key(lower_key)
}

is_sensitive_key_pattern(key) {
    lower_key := lower(key)
    suffixes := {"password", "secret", "key", "token", "api_key", "secret_key", "access_key", 
                "private_key", "secret_value", "admin_password", "db_password", "encryption_key", 
                "signing_key", "ssh_private_key", "auth_token", "bearer_token", "shared_secret", 
                "connection_string", "db_url", "username", "endpoint_credentials", 
                "deploy_token", "ci_cd_secret", "webhook_secret", "github_token", "sha512_password",
                "keystore_password", "truststore_password", "rbd_secret_uuid"}
    some suffix in suffixes
    endswith(lower_key, suffix)
}

is_sensitive_key_pattern(key) {
    lower_key := lower(key)
    suffixes := {"password", "secret", "key", "token", "api_key", "secret_key", "access_key", 
                "private_key", "secret_value", "admin_password", "db_password", "encryption_key", 
                "signing_key", "ssh_private_key", "auth_token", "bearer_token", "shared_secret", 
                "connection_string", "db_url", "username", "endpoint_credentials", 
                "deploy_token", "ci_cd_secret", "webhook_secret", "github_token", "sha512_password",
                "keystore_password", "truststore_password", "rbd_secret_uuid"}
    some suffix in suffixes
    endswith(lower_key, "_" + suffix)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type in {"Attribute", "Variable"}
    
    key := node.name
    key_name := extract_key_name(key)
    is_sensitive_key_pattern(key_name)
    
    value := node.value
    is_hardcoded_string(value)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credential found in attribute or variable. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type in {"Attribute", "Variable"}
    
    key := node.name
    key_name := extract_key_name(key)
    is_sensitive_key_pattern(key_name)
    
    value := node.value
    is_default_string(value)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded default credential found in attribute or variable. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, hash_node])
    hash_node.ir_type == "Hash"
    pair := hash_node.value[_]
    key_expr := pair.key
    key_expr.ir_type == "String"
    
    is_sensitive_key_pattern(key_expr.value)
    
    value_expr := pair.value
    is_hardcoded_string(value_expr)
    
    result := {
        "type": "sec_hard_secr",
        "element": key_expr,
        "path": parent.path,
        "description": "Hard-coded credential found in Hash key-value pair. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, hash_node])
    hash_node.ir_type == "Hash"
    pair := hash_node.value[_]
    key_expr := pair.key
    key_expr.ir_type == "String"
    
    is_sensitive_key_pattern(key_expr.value)
    
    value_expr := pair.value
    is_default_string(value_expr)
    
    result := {
        "type": "sec_hard_secr",
        "element": key_expr,
        "path": parent.path,
        "description": "Hard-coded default credential found in Hash key-value pair. (CWE-798)"
    }
}