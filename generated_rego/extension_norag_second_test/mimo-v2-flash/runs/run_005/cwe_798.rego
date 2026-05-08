package glitch

import data.glitch_lib

sensitive_keywords := {"password", "pass", "pwd", "secret", "api_key", "apikey", "token", "access_key", "secret_key", "secret_token", "auth_token", "private_key", "client_certificate", "ssl_key", "ssh_key", "jwt_secret", "encryption_key", "connection_string", "dsn", "jdbc_url"}

is_sensitive_name(name) {
    some keyword
    sensitive_keywords[keyword]
    regex.match(sprintf("(?i).*%s.*", [keyword]), name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    key_name := node.name
    is_sensitive_name(key_name)
    node.value.ir_type == "String"
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": sprintf("Hard-coded credential found in variable or attribute '%s'. (CWE-798)", [key_name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    key_name := node.key.value
    is_sensitive_name(key_name)
    node.value.ir_type == "String"
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": sprintf("Hard-coded credential found in key '%s'. (CWE-798)", [key_name])
    }
}