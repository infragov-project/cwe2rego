package glitch

import data.glitch_lib

credential_names := {"password", "passwd", "pwd", "secret", "api_key", "apikey", "api_secret", "access_key", "secret_key", "client_secret", "auth_token", "bearer_token", "token", "private_key", "ssh_key", "key_file", "cert_pem", "private_key_pem", "credentials", "basic_auth", "http_auth", "login", "authentication", "encryption_key", "master_key", "salt", "signing_key", "jwt_secret", "hmac_key", "connection_string", "database_url", "mongo_uri", "redis_url", "keystore_password", "truststore_password"}

weak_values := {"null", "none", "", "true", "false", "yes", "no", "present", "absent", "enabled", "disabled"}

is_credential_name(name) {
    lower_name := lower(name)
    some cn in credential_names
    lower_name == cn
}

is_credential_name(name) {
    lower_name := lower(name)
    endswith(lower_name, "_password")
}

is_credential_name(name) {
    lower_name := lower(name)
    endswith(lower_name, "_secret")
}

is_credential_name(name) {
    lower_name := lower(name)
    endswith(lower_name, "_key")
}

is_credential_name(name) {
    lower_name := lower(name)
    endswith(lower_name, "_token")
}

is_credential_name(name) {
    lower_name := lower(name)
    contains(lower_name, "password")
}

is_credential_name(name) {
    lower_name := lower(name)
    contains(lower_name, "_secret_")
}

is_credential_name(name) {
    lower_name := lower(name)
    contains(lower_name, "credential")
}

get_leaf_dotted(name) = leaf {
    parts := split(name, ".")
    count(parts) > 0
    leaf := parts[minus(count(parts), 1)]
}

get_leaf_bracket(name) = leaf {
    contains(name, "['")
    parts := split(name, "['")
    count(parts) > 0
    last := parts[minus(count(parts), 1)]
    leaf := trim(last, "']")
}

get_leaf_bracket(name) = leaf {
    contains(name, "[\"")
    parts := split(name, "[\"")
    count(parts) > 0
    last := parts[minus(count(parts), 1)]
    leaf := trim(last, "\"]")
}

get_all_leaves(name) = leaves {
    dotted := {l | l := get_leaf_dotted(name)}
    bracket := {l | l := get_leaf_bracket(name)}
    leaves := dotted | bracket | {name}
}

matches_credential_pattern(name) {
    leaves := get_all_leaves(name)
    some leaf in leaves
    is_credential_name(leaf)
}

is_weak_or_empty(val) {
    some wv in weak_values
    lower(val) == wv
}

is_weak_or_empty(val) {
    count(val) == 0
}

is_path_pattern(val) {
    regex.match(`^(~/)?(/[a-zA-Z0-9._-]+)+/?$`, val)
}

is_dn_pattern(val) {
    regex.match(`^[a-z]+=[^,]+(,[a-z]+=[^,]+)*$`, val)
}

is_common_config(val) {
    regex.match(`^(true|false|yes|no|present|absent|enabled|disabled|[0-9]+|/.+|\$[0-9].*)$`, val)
}

is_literal_key_method(key, val) {
    lower(key) == "key"
    lower(val) == "key"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Hash"
    
    some entry in node.value
    entry.key.ir_type == "String"
    key_name := entry.key.value
    
    entry.value.ir_type == "String"
    val := entry.value.value
    
    is_credential_name(key_name)
    not is_weak_or_empty(val)
    not is_path_pattern(val)
    not is_dn_pattern(val)
    not is_common_config(val)
    not is_literal_key_method(key_name, val)
    
    result := {
        "type": "sec_hard_secr",
        "element": entry,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be embedded directly in configuration files. Use secure external sources or parameterization mechanisms. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    some var in vars
    
    matches_credential_pattern(var.name)
    
    var.value.ir_type == "String"
    val := var.value.value
    
    not is_weak_or_empty(val)
    not is_path_pattern(val)
    not is_dn_pattern(val)
    not is_common_config(val)
    not is_literal_key_method(var.name, val)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be embedded directly in configuration files. Use secure external sources or parameterization mechanisms. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    
    matches_credential_pattern(node.name)
    
    node.value.ir_type == "String"
    val := node.value.value
    
    not is_weak_or_empty(val)
    not is_path_pattern(val)
    not is_dn_pattern(val)
    not is_common_config(val)
    not is_literal_key_method(node.name, val)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be embedded directly in configuration files. Use secure external sources or parameterization mechanisms. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, ub])
    ub.ir_type == "UnitBlock"
    
    some attr in ub.attributes
    
    matches_credential_pattern(attr.name)
    
    attr.value.ir_type == "String"
    val := attr.value.value
    
    not is_weak_or_empty(val)
    not is_path_pattern(val)
    not is_dn_pattern(val)
    not is_common_config(val)
    not is_literal_key_method(attr.name, val)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be embedded directly in configuration files. Use secure external sources or parameterization mechanisms. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    units := glitch_lib.all_atomic_units(parent)
    some unit in units
    
    some attr in unit.attributes
    
    matches_credential_pattern(attr.name)
    
    attr.value.ir_type == "String"
    val := attr.value.value
    
    not is_weak_or_empty(val)
    not is_path_pattern(val)
    not is_dn_pattern(val)
    not is_common_config(val)
    not is_literal_key_method(attr.name, val)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be embedded directly in configuration files. Use secure external sources or parameterization mechanisms. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Hash"
    
    some entry in node.value
    entry.key.ir_type == "String"
    key_name := entry.key.value
    
    entry.value.ir_type == "String"
    val := entry.value.value
    
    contains(lower(key_name), "connection_string")
    regex.match(`^[a-z]+://[^:]+:[^@]+@`, val)
    
    result := {
        "type": "sec_hard_secr",
        "element": entry,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Credentials should not be embedded directly in configuration files. Use secure external sources or parameterization mechanisms. (CWE-798)"
    }
}