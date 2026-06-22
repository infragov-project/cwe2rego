package glitch

import data.glitch_lib

credential_keywords := {"auth", "authentication", "credential", "cred", "login", "signin", "token", "oauth", "api_key", "apikey", "secret_key", "access_key", "password", "passwd", "pwd", "passphrase", "secret", "client_secret", "admin_password", "root_password", "private_key", "key_data", "ssh_key", "signing_key", "db_password", "database_url", "connection_string", "jdbc_url", "mongo_uri", "redis_auth", "service_account", "assume_role", "sha512_password", "sha256_password", "md5_password", "user_password", "bind_password", "ldap_password", "keystore_password", "truststore_password", "key_password", "store_password"}
credential_exact := {"key", "cert", "certificate", "key_file", "tls_cert", "subscription_id", "tenant_id", "client_id", "iam_role", "keystore", "truststore"}
suffix := {"_key", "_secret", "_token", "_password", "_pwd", "_auth", "_cert", "_store"}
safe_reference_patterns := {"var.", "variable.", "local.", "data.", "module.", "env(", "getenv", "environment", "vault", "secretmanager", "key_vault", "kms", "parameter", "secure_string", "sensitive(", "file(", "templatefile("}

schema_field_patterns := {"_tree_dn", "_objectclass", "_id_attribute", "_name_attribute", "_mail_attribute", "_allow_create", "_allow_update", "_allow_delete", "_member_attribute", "_desc_attribute", "_enabled_attribute", "_enabled_default", "_enabled_invert", "_cacertfile", "user_tree_dn", "group_tree_dn", "user_objectclass", "group_objectclass", "authenticator", "authorizer", "url", "uri", "host", "port", "server", "method", "type", "driver", "scheme", "version", "name", "description", "comment", "label", "tag"}

common_usernames := {"Administrator", "root", "admin", "user", "true", "false", "True", "False", "yes", "no", "on", "off", "enabled", "disabled", "default", "standard", "normal", "compute", "cassandra", "sensu"}

is_schema_field(name) {
    lower_name := lower(name)
    pattern := schema_field_patterns[_]
    contains(lower_name, pattern)
}

is_credential_field(name) {
    lower_name := lower(name)
    not is_schema_field(lower_name)
    keyword := credential_keywords[_]
    contains(lower_name, keyword)
} else {
    lower_name := lower(name)
    not is_schema_field(lower_name)
    exact := credential_exact[_]
    lower_name == exact
} else {
    lower_name := lower(name)
    not is_schema_field(lower_name)
    s := suffix[_]
    endswith(lower_name, s)
}

is_safe_reference(value) {
    value.ir_type == "VariableReference"
    ref := value.value
    pattern := safe_reference_patterns[_]
    contains(ref, pattern)
}

is_safe_reference(value) {
    value.ir_type == "FunctionCall"
    name := lower(value.name)
    pattern := safe_reference_patterns[_]
    contains(name, pattern)
}

is_common_username(val) {
    lower(val) == lower(common_usernames[_])
} else {
    regex.match(`^(?i)(cn=|uid=|ou=|dc=|o=|availability|up|down|ok|none|null|default)$`, val)
}

looks_like_credential_value(value) {
    value.ir_type == "String"
    val := value.value
    count(val) > 0
    not is_common_username(val)
} else {
    value.ir_type == "String"
    val := value.value
    count(val) > 0
    regex.match(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, val)
}

extract_last_segment(name) = last {
    parts := split(name, ".")
    count(parts) > 0
    last = parts[count(parts) - 1]
} else = last {
    matches := regex.find_all_string_submatch_n(`\['([^']+)'\]$`, name, 1)
    count(matches) > 0
    count(matches[0]) > 1
    last = matches[0][1]
} else = last {
    matches := regex.find_all_string_submatch_n(`\["([^"]+)"\]$`, name, 1)
    count(matches) > 0
    count(matches[0]) > 1
    last = matches[0][1]
} else = name {
    true
}

check_credential_in_hash_entry(key_node, val_node) {
    key_node.ir_type == "String"
    key_name := key_node.value
    is_credential_field(key_name)
    val_node.ir_type == "String"
    looks_like_credential_value(val_node)
    not is_safe_reference(val_node)
}

collect_all_hash_nodes(node) = hash_nodes {
    hash_nodes := {n |
        walk(node, [_, n])
        n.ir_type == "Hash"
    }
}

collect_direct_creds_in_hash(hash_node, base_path) = creds {
    creds := {cred |
        entry := hash_node.value[_]
        k := entry.key
        v := entry.value
        k.ir_type == "String"
        is_credential_field(k.value)
        v.ir_type == "String"
        looks_like_credential_value(v)
        not is_safe_reference(v)
        path := sprintf("%s.%s", [base_path, k.value])
        cred := [k.value, v, path]
    }
}

all_creds_in_node(node, path_str) = creds {
    node.ir_type == "Hash"
    hash_nodes := collect_all_hash_nodes(node)
    
    creds := {cred |
        hash_node := hash_nodes[_]
        hash_node_node := hash_node
        
        entry := hash_node_node.value[_]
        k := entry.key
        v := entry.value
        
        k.ir_type == "String"
        is_credential_field(k.value)
        v.ir_type == "String"
        looks_like_credential_value(v)
        not is_safe_reference(v)
        
        full_path := sprintf("%s.%s", [path_str, k.value])
        cred := [k.value, v, full_path]
    }
}

all_creds_in_node(node, path_str) = creds {
    node.ir_type == "Array"
    array_nodes := {n |
        walk(node, [_, n])
        n.ir_type == "Hash"
    }
    
    creds := {cred |
        hash_node := array_nodes[_]
        
        entry := hash_node.value[_]
        k := entry.key
        v := entry.value
        
        k.ir_type == "String"
        is_credential_field(k.value)
        v.ir_type == "String"
        looks_like_credential_value(v)
        not is_safe_reference(v)
        
        path := sprintf("%s.%s", [path_str, k.value])
        cred := [k.value, v, path]
    }
}

all_creds_in_node(node, path_str) = creds {
    not node.ir_type == "Hash"
    not node.ir_type == "Array"
    creds := set()
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Variable"
    node.value.ir_type == "Hash"
    
    creds := all_creds_in_node(node.value, node.name)
    count(creds) > 0
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of hard-coded credentials (field: %s) - Credentials should not be hard-coded in configuration files. Use environment variables, secret management systems, or dynamic configuration sources instead. (CWE-798)", [node.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Variable"
    node.value.ir_type == "String"
    
    check_credential_in_name(node.name, node.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of hard-coded credentials (field: %s) - Credentials should not be hard-coded in configuration files. Use environment variables, secret management systems, or dynamic configuration sources instead. (CWE-798)", [node.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "Array"
    
    creds := all_creds_in_node(node.value, node.name)
    count(creds) > 0
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of hard-coded credentials (field: %s) - Credentials should not be hard-coded in configuration files. Use environment variables, secret management systems, or dynamic configuration sources instead. (CWE-798)", [node.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "String"
    
    check_credential_in_name(node.name, node.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of hard-coded credentials (field: %s) - Credentials should not be hard-coded in configuration files. Use environment variables, secret management systems, or dynamic configuration sources instead. (CWE-798)", [node.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "Hash"
    
    creds := all_creds_in_node(node.value, node.name)
    count(creds) > 0
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": sprintf("Use of hard-coded credentials (field: %s) - Credentials should not be hard-coded in configuration files. Use environment variables, secret management systems, or dynamic configuration sources instead. (CWE-798)", [node.name])
    }
}

check_credential_in_name(name, value) {
    not is_schema_field(name)
    is_credential_field(name)
    value.ir_type == "String"
    looks_like_credential_value(value)
    not is_safe_reference(value)
}