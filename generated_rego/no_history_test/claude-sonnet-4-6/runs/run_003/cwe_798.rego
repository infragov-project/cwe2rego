package glitch

import data.glitch_lib

credential_field_pattern := `(?i).*(password|passwd|pwd|pass|secret|token|api_key|apikey|access_key|secret_access_key|auth_token|access_token|bearer_token|service_token|private_key|signing_key|encryption_key|crypto_key|ssh_key|tls_key|ssl_key|kms_key|aes_key|rsa_key|client_secret|app_secret|key_material|connection_string|conn_str|jdbc_url|db_url|database_url|connection_uri|dsn|credential|keystore|truststore).*`

credential_word_pattern := `(?i)(^|\.|_)(key|user|username|login|auth|pass)(\.|_|$)`

is_sensitive_name(name) {
    regex.match(credential_field_pattern, name)
}

is_sensitive_name(name) {
    regex.match(credential_word_pattern, name)
}

is_plain_string_value(val) {
    val.ir_type == "String"
    val.value != ""
    not regex.match(`^(/|[A-Za-z]:[/\\])`, val.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_sensitive_name(attr.name)
    is_plain_string_value(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be stored as plain text in IaC scripts. Use a secrets manager or vault reference instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_sensitive_name(v.name)
    is_plain_string_value(v.value)
    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be stored as plain text in IaC scripts. Use a secrets manager or vault reference instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    is_sensitive_name(entry.key.value)
    is_plain_string_value(entry.value)
    result := {
        "type": "sec_hard_secr",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Hard-coded credentials found in map/hash structure. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(`(?i).*-----BEGIN.*`, node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - PEM-formatted key or certificate found as plain text in IaC script. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(`(?i).*(password=|pwd=|passwd=)`, node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Connection string contains embedded credentials in plain text. (CWE-798)"
    }
}