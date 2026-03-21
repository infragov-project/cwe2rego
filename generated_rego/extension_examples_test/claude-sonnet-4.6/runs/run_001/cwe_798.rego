package glitch

import data.glitch_lib

credential_substr_pattern := `(?i)(password|passwd|pwd|secret|api_key|apikey|api_token|access_key|access_token|auth_token|bearer_token|service_token|webhook_secret|client_secret|oauth_secret|oauth_token|private_key|signing_key|encryption_key|ssl_key|tls_key|ssh_key|rsa_key|shared_secret|pre_shared_key|community_string|snmp_community|psk|github_token|webhook_token|token|truststore|keystore|key)`

credential_word_pattern := `(?i)\b(user|username|login|credential|credentials)\b`

connection_url_pattern := `(?i)(connection_string|connectionstring|connection_url|database_url|db_url|jdbc_url|dsn|data_source)`

bootstrap_pattern := `(?i)(user_data|custom_data|cloud_init|startup_script|init_script|bootstrap)`

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
}

is_sensitive_name(name) {
    regex.match(credential_substr_pattern, name)
}

is_sensitive_name(name) {
    regex.match(credential_word_pattern, name)
}

is_file_path(value) {
    value.ir_type == "String"
    regex.match(`^(/|~/|\.\/)`, value.value)
}

is_ldap_dn_value(value) {
    value.ir_type == "String"
    regex.match(`(?i)^[a-zA-Z][a-zA-Z0-9\-]*=[^,]+(,[a-zA-Z][a-zA-Z0-9\-]*=.+)+$`, value.value)
}

has_embedded_credentials(value) {
    value.ir_type == "String"
    regex.match(`(?i)(uid=|pwd=|password=|user=|username=)`, value.value)
}

has_embedded_credentials(value) {
    value.ir_type == "String"
    regex.match(`[a-zA-Z][a-zA-Z0-9+\-.]*://[^:@ ]+:[^@ ]+@`, value.value)
}

has_crypto_material(value) {
    value.ir_type == "String"
    regex.match(`-----BEGIN `, value.value)
}

has_credential_in_script(value) {
    value.ir_type == "String"
    regex.match(`(?i)(PASSWORD|API_KEY|SECRET|TOKEN)\s*=\s*\S`, value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_sensitive_name(attr.name)
    is_hardcoded_string(attr.value)
    not is_file_path(attr.value)
    not is_ldap_dn_value(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Sensitive attribute contains a literal string value. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_sensitive_name(var.name)
    is_hardcoded_string(var.value)
    not is_file_path(var.value)
    not is_ldap_dn_value(var.value)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Sensitive variable contains a literal string value. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.key.ir_type == "String"
    is_sensitive_name(node.key.value)
    node.value.ir_type == "String"
    node.value.value != ""
    not is_file_path(node.value)
    not is_ldap_dn_value(node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials in nested configuration. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(connection_url_pattern, attr.name)
    has_embedded_credentials(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials in connection string. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    has_crypto_material(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded cryptographic material. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(bootstrap_pattern, attr.name)
    has_credential_in_script(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials in bootstrap script. (CWE-798)"
    }
}