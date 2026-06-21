package glitch

import data.glitch_lib

is_credential_field(name) {
    regex.match("(?i).*(password|passwd|pwd|pass|secret|api_key|apikey|api_secret|access_token|auth_token|bearer_token|refresh_token|service_token|api_token|access_key|secret_access_key|private_key|key_pem|tls_key|ssl_key|encryption_key|decryption_key|signing_key|connection_string|conn_str|db_uri|jdbc_url|database_url|credentials|credential|auth_string|auth_key|authentication_token|ssh_key|ssh_private_key|authorized_key|identity_file|community_string|snmp_community|snmp_auth_password|account_key|account_secret|private_key_id|keystore|truststore|username).*", name)
}

is_credential_field(name) {
    regex.match("(?i)(^|.*[._])key([._].*|$)", name)
}

is_credential_field(name) {
    regex.match("(?i)(^|\\.)user$", name)
}

is_hardcoded_value(value) {
    value.ir_type == "String"
    value.value != ""
    not regex.match("^/", value.value)
    not regex.match("(?i)^[a-z]+=.+,", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.key.ir_type == "String"
    is_credential_field(node.key.value)
    is_hardcoded_value(node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credential fields should not contain literal string values. Use a secrets management system or environment variables instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, v])
    v.ir_type == "Variable"
    is_credential_field(v.name)
    is_hardcoded_value(v.value)
    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credential fields should not contain literal string values. Use a secrets management system or environment variables instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    is_credential_field(attr.name)
    is_hardcoded_value(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credential fields should not contain literal string values. Use a secrets management system or environment variables instead. (CWE-798)"
    }
}