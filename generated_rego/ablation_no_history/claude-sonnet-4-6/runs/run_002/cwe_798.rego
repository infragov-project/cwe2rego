package glitch

import data.glitch_lib

sensitive_keywords := {
    "password", "passwd", "pwd", "passphrase", "pass",
    "secret", "token", "key",
    "api_key", "api_secret", "api_token",
    "access_key", "secret_key", "secret_access_key",
    "auth_token", "bearer_token", "oauth_token",
    "private_key", "encryption_key", "signing_key",
    "credential", "credentials",
    "connection_string", "connection_url", "database_url",
    "db_url", "dsn", "mongo_uri", "redis_url",
    "basic_auth", "client_secret", "webhook_secret", "app_secret"
}

is_sensitive_name(name) {
    lower_name := lower(name)
    kw := sensitive_keywords[_]
    regex.match(sprintf("(^|[^a-z0-9])%s([^a-z0-9]|$)", [kw]), lower_name)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
    not glitch_lib.has_variable_reference(value)
    not regex.match("^\\$\\{", value.value)
    not regex.match("^/", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    kv.ir_type == "Variable"
    is_sensitive_name(kv.name)
    is_hardcoded_string(kv.value)
    result := {
        "type": "sec_hard_secr",
        "element": kv,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be embedded as literal values in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    kv.ir_type == "Attribute"
    kv.value.ir_type != "BlockExpr"
    is_sensitive_name(kv.name)
    is_hardcoded_string(kv.value)
    result := {
        "type": "sec_hard_secr",
        "element": kv,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be embedded as literal values in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    is_sensitive_name(entry.key.value)
    is_hardcoded_string(entry.value)
    result := {
        "type": "sec_hard_secr",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be embedded as literal values in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(".*-----BEGIN.*PRIVATE KEY-----.*", node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - PEM private key material embedded in IaC script. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(".*://[^@\\s]+:[^@\\s]+@.*", node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials embedded in connection URI. (CWE-798)"
    }
}