package glitch

import data.glitch_lib

credential_field_pattern := "(?i)(password|passwd|pwd|passphrase|username|\\buser\\b|\\blogin\\b|secret|auth_token|access_token|api_token|bearer_token|refresh_token|api_key|apikey|api_secret|app_secret|client_secret|shared_secret|private_key|key_material|ssh_private_key|rsa_private_key|cert_pem|tls_cert|ssl_cert|encryption_key|hmac_key|signing_key|connection_string|database_url|db_url|jdbc_url|master_password|admin_password|db_password|root_password|user_password|keystore|truststore|\\btoken\\b|\\bkey\\b)"

non_credential_field_suffix := "(?i).*(cacertfile|_file|_filepath|_path|_dir|_directory|_template|_attribute|_objectclass|_type|_list|_format|_mode|_size|_timeout|_version|_level|_dn|_domain|_domain_name|_data|_agent|_id|_count)$"

is_credential_field(name) {
    regex.match(credential_field_pattern, name)
    not regex.match(non_credential_field_suffix, name)
}

is_ldap_dn(str) {
    regex.match("(?i)^(uid|cn|dc|ou|o|l|st|c|mail|sn|gn)=[^,]+,", str)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
    not startswith(value.value, "/")
    not is_ldap_dn(value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_credential_field(node.name)
    is_hardcoded_string(node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credential fields should not contain literal string values. Use a secrets manager or variable references instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    is_credential_field(node.name)
    is_hardcoded_string(node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credential fields should not contain literal string values. Use a secrets manager or variable references instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    is_credential_field(entry.key.value)
    entry.value.ir_type == "String"
    entry.value.value != ""
    not startswith(entry.value.value, "/")
    not is_ldap_dn(entry.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credential fields should not contain literal string values. Use a secrets manager or variable references instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "String"
    regex.match("(?s).*-----BEGIN [A-Z ]+-----.*", node.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Embedded cryptographic material - Private keys or certificates should not be hard-coded inline. (CWE-798)"
    }
}