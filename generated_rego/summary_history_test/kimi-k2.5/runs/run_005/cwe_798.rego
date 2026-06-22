package glitch

import data.glitch_lib

credential_keywords := {
    "password", "passwd", "pwd", "secret", "secret_key", "secrets",
    "token", "api_token", "auth_token", "bearer_token", "access_token",
    "api_key", "apikey", "access_key", "key",
    "credentials", "credential",
    "private_key", "public_key", "certificate", "cert",
    "conn_string", "connection_string",
    "db_password", "database_password", "root_password", "admin_password",
    "master_key", "encryption_key", "signing_key", "shared_key", "session_key",
    "keystore_password", "truststore_password", "keystore_pass", "truststore_pass",
    "initial_password", "setup_password", "bootstrap_password",
    "service_password", "user_password", "manager_password",
    "passphrase", "pass",
    "sha512_password", "sha256_password", "encrypted_password", "hashed_password"
}

sensitive_contexts := {
    "auth", "authentication", "login", "credential", "credentials",
    "security", "private", "secret", "encrypt", "encryption",
    "keystore", "truststore", "cert", "certificate", "ssl", "tls",
    "sign", "signature", "signing", "verify", "verification",
    "rabbitmq", "cassandra", "rbd", "bgp", "ldap", "cvauth", "user", "pass",
    "bgp", "peer", "peer_group", "neighbors", "terminattr", "cvpadmin", "admin",
    "local_users", "sensu", "keystone", "backend"
}

common_usernames := {
    "root", "admin", "administrator", "sensu", "guest", "user", "test", "temp",
    "localhost", "api", "service", "system"
}

looks_like_secret_manager_ref(value) {
    regex.match("^(var|data|module|local|each|path|terraform|aws_secretsmanager|azurerm_key_vault|vault_|lookup)\\.", value)
} else {
    regex.match("^\\$\\{", value)
} else {
    regex.match("^\\{\\{", value)
}

is_path_or_dn(value) {
    startswith(lower(value), "/")
} else {
    startswith(lower(value), "cn=")
} else {
    startswith(lower(value), "uid=")
} else {
    startswith(lower(value), "ou=")
} else {
    startswith(lower(value), "dc=")
} else {
    startswith(lower(value), "o=")
} else {
    startswith(lower(value), "ldaps://")
} else {
    startswith(lower(value), "ldap://")
} else {
    regex.match("^[a-z]+://", lower(value))
}

looks_like_encoded_or_hash(value) {
    regex.match("^\\$[0-9a-z]+\\$", value)
} else {
    regex.match("[A-Za-z0-9+/]{20,}={0,2}$", value)
}

is_common_username(value) {
    lower_val := lower(value)
    lower_val == common_usernames[_]
}

is_short_common_word(value) {
    lower_val := lower(value)
    lower_val == "true"
} else {
    lower_val := lower(value)
    lower_val == "false"
} else {
    lower_val := lower(value)
    lower_val == "yes"
} else {
    lower_val := lower(value)
    lower_val == "no"
} else {
    lower_val := lower(value)
    lower_val == "on"
} else {
    lower_val := lower(value)
    lower_val == "off"
} else {
    lower_val := lower(value)
    lower_val == "null"
} else {
    lower_val := lower(value)
    lower_val == "none"
} else {
    lower_val := lower(value)
    lower_val == "nil"
}

extract_dotted_components(name) = parts {
    parts := split(name, ".")
}

extract_bracket_components(name) = parts {
    parts := regex.split("\\['|']", name)
}

get_all_name_parts(name) = parts {
    dotted := extract_dotted_components(name)
    parts := {part | part := dotted[_]; part != ""}
} else = parts {
    bracket := extract_bracket_components(name)
    parts := {trim(part, "'\"") | part := bracket[_]; part != ""}
}

key_matches_credential_keyword(key_str) {
    kw := credential_keywords[_]
    key_str == kw
} else {
    kw := credential_keywords[_]
    endswith(key_str, concat("", ["_", kw]))
} else {
    kw := credential_keywords[_]
    startswith(key_str, concat("", [kw, "_"]))
}

name_contains_cred_keyword(full_name) {
    parts := get_all_name_parts(full_name)
    some part
    part = parts[_]
    some kw
    kw = credential_keywords[_]
    lower_part := lower(part)
    lower_part == kw
} else {
    parts := get_all_name_parts(full_name)
    some part
    part = parts[_]
    some kw
    kw = credential_keywords[_]
    lower_part := lower(part)
    endswith(lower_part, concat("", ["_", kw]))
} else {
    parts := get_all_name_parts(full_name)
    some part
    part = parts[_]
    some kw
    kw = credential_keywords[_]
    lower_part := lower(part)
    startswith(lower_part, concat("", [kw, "_"]))
}

has_sensitive_context(full_name) {
    lower_key := lower(full_name)
    ctx := sensitive_contexts[_]
    contains(lower_key, ctx)
}

is_likely_credential_value(val) {
    val != ""
    count(val) > 1
    not is_short_common_word(val)
    not is_path_or_dn(val)
    not looks_like_secret_manager_ref(val)
}

should_skip_contextual_detection(key_name, val) {
    is_common_username(val)
} else {
    has_sensitive_context(key_name)
    not regex.match("[^a-zA-Z0-9]", val)
    count(val) < 20
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Variable"
    
    var_name := node.name
    var_value := node.value
    
    var_value.ir_type == "String"
    
    name_contains_cred_keyword(var_name)
    
    val_str := var_value.value
    is_likely_credential_value(val_str)
    not should_skip_contextual_detection(var_name, val_str)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hard-coded in configuration. Use secret management solutions instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    
    attr_name := node.name
    attr_value := node.value
    
    attr_value.ir_type == "String"
    
    name_contains_cred_keyword(attr_name)
    
    val_str := attr_value.value
    is_likely_credential_value(val_str)
    not should_skip_contextual_detection(attr_name, val_str)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hard-coded in configuration. Use secret management solutions instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "KeyValue"
    node.key.ir_type == "String"
    
    key_str := lower(node.key.value)
    val_node := node.value
    
    val_node.ir_type == "String"
    val_str := val_node.value
    
    key_matches_credential_keyword(key_str)
    
    is_likely_credential_value(val_str)
    not should_skip_contextual_detection(key_str, val_str)
    
    result := {
        "type": "sec_hard_secr",
        "element": val_node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be hard-coded in configuration. Use secret management solutions instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    
    walk(hash_node.value, [_, kv])
    kv.ir_type == "KeyValue"
    kv.key.ir_type == "String"
    
    inner_key := lower(kv.key.value)
    inner_val := kv.value
    
    inner_val.ir_type == "String"
    val_str := inner_val.value
    
    key_matches_credential_keyword(inner_key)
    
    is_likely_credential_value(val_str)
    not should_skip_contextual_detection(inner_key, val_str)
    
    result := {
        "type": "sec_hard_secr",
        "element": inner_val,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials in nested hash structure. Use secret management solutions instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, var_node])
    var_node.ir_type == "Variable"
    
    var_name := var_node.name
    
    not name_contains_cred_keyword(var_name)
    has_sensitive_context(var_name)
    
    var_value := var_node.value
    var_value.ir_type == "String"
    val_str := var_value.value
    
    is_likely_credential_value(val_str)
    count(val_str) > 6
    not is_common_username(val_str)
    
    result := {
        "type": "sec_hard_secr",
        "element": var_node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Potential credential in sensitive security context. Use secret management solutions instead. (CWE-798)"
    }
}

hash_deep_scan(hash_contents, prefix) = {[key, val] |
    walk(hash_contents, [_, kv])
    kv.ir_type == "KeyValue"
    kv.key.ir_type == "String"
    kv.value.ir_type == "String"
    key := concat(".", [prefix, kv.key.value])
    val := kv.value.value
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, var_node])
    var_node.ir_type == "Variable"
    
    var_name := var_node.name
    var_value := var_node.value
    
    var_value.ir_type == "Hash"
    
    pair := hash_deep_scan(var_value.value, var_name)[_]
    inner_key := pair[0]
    inner_val := pair[1]
    
    key_matches_credential_keyword(lower(inner_key))
    
    is_likely_credential_value(inner_val)
    not should_skip_contextual_detection(inner_key, inner_val)
    
    result := {
        "type": "sec_hard_secr",
        "element": var_node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials in deeply nested structure. Use secret management solutions instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "BlockExpr"
    
    walk(node.statements, [_, stmt])
    stmt.ir_type == "KeyValue"
    stmt.key.ir_type == "String"
    
    key_str := lower(stmt.key.value)
    val_node := stmt.value
    
    val_node.ir_type == "String"
    val_str := val_node.value
    
    key_matches_credential_keyword(key_str)
    
    is_likely_credential_value(val_str)
    not should_skip_contextual_detection(key_str, val_str)
    
    result := {
        "type": "sec_hard_secr",
        "element": val_node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials in block expression. Use secret management solutions instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, stmt])
    stmt.ir_type == "ConditionalStatement"
    
    walk(stmt.statements, [_, inner_stmt])
    walk(inner_stmt, [_, inner_node])
    
    inner_node.ir_type == "Variable"
    
    inner_value := inner_node.value
    inner_value.ir_type == "String"
    inner_val := inner_value.value
    
    name_contains_cred_keyword(inner_node.name)
    
    is_likely_credential_value(inner_val)
    not should_skip_contextual_detection(inner_node.name, inner_val)
    
    result := {
        "type": "sec_hard_secr",
        "element": inner_node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials in conditional statement. Use secret management solutions instead. (CWE-798)"
    }
}