package glitch

import data.glitch_lib

sensitive_patterns = {"password", "secret", "key", "token", "credential", "auth", "api_key", "api_token", "access_key", "secret_key", "private_key", "connection_string", "ssh_private_key", "bearer_token", "keystore_password", "truststore_password", "store_password", "passwd", "pass", "apikey", "accesstoken", "refreshtoken", "client_secret", "encryption_key", "signing_key", "database_password", "db_password", "db_pass", "user", "username", "keystore", "truststore", "client_id", "tenant_id", "subscription_id", "project_id", "account_id", "role_id", "group_id", "secret_id", "key_id", "token_id", "access_token", "refresh_token", "id_token", "client_certificate", "client_key", "server_certificate", "root_certificate", "ca_certificate", "private_key_password", "key_password", "salt", "iv", "nonce", "session_key", "signing_secret", "webhook_secret", "verification_token", "reset_token", "activation_token", "email_token", "jwt_secret", "cookie_secret", "csrf_secret", "encryption_password", "decryption_key", "master_key", "data_key", "wrap_key", "unwrap_key", "signing_key_id", "encryption_key_id", "decryption_key_id", "hmac_key", "hmac_secret", "api_secret", "api_token_secret", "consumer_secret", "access_token_secret", "refresh_token_secret", "client_secret_key", "shared_secret", "password_hash", "secret_hash", "key_hash", "token_hash", "credential_hash", "auth_hash"}

is_sensitive_key(key) {
    pattern := sensitive_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), key)
}

is_hardcoded_string(str) {
    str != ""
    not regex.match(".*\\$\\{.*", str)
    not regex.match(".*\\{\\{.*", str)
    not regex.match(".*&.*", str)
    not regex.match(".*\\*.*", str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    node.ir_type == "Variable"
    is_sensitive_key(node.name)
    node.value.ir_type == "String"
    is_hardcoded_string(node.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credential in variable - Avoid hard-coded credentials in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    is_sensitive_key(node.name)
    node.value.ir_type == "String"
    is_hardcoded_string(node.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credential in attribute - Avoid hard-coded credentials in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [path, node])
    node.ir_type == "KeyValue"
    is_sensitive_key(node.name)
    node.value.ir_type == "String"
    is_hardcoded_string(node.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hard-coded credential in key-value pair - Avoid hard-coded credentials in IaC scripts. (CWE-798)"
    }
}