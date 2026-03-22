package glitch

import data.glitch_lib

credential_name_pattern := `(?i).*(password|passwd|pwd|secret|token|api_key|apikey|api_secret|credential|private_key|ssl_key|tls_key|ssh_key|encryption_key|signing_key|key_material|key_data|key_pem|certificate|access_key|account_key|storage_key|client_secret|sas_token|connection_string|database_url|db_url|jdbc_url|auth_token|bearer_token|keystore|truststore|username).*`

file_ref_pattern := `(?i).*(cacertfile|certfile|_xml|_file|_path|_dir)$`

is_secret_ref(str) {
    regex.match(`\$\{|\{\{|#\{`, str)
}

is_secret_ref(str) {
    regex.match(`(?i)(vault://|azurekeyvault://|ssm://|arn:.*:secretsmanager:|projects/.*/secrets/)`, str)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    count(value.value) > 0
    not is_secret_ref(value.value)
}

is_credential_name(name) {
    regex.match(credential_name_pattern, name)
    not regex.match(file_ref_pattern, name)
}

is_user_name(name) {
    regex.match(`(?i)^(user|login)$`, name)
}

is_user_name(name) {
    regex.match(`(?i)\.(user|login)$`, name)
}

is_user_name(name) {
    regex.match(`(?i)\[['"]?(user|login)['"]?\]$`, name)
}

is_standalone_key_field(name) {
    regex.match(`(?i)^key$`, name)
}

is_hardcoded_credential(name, value) {
    is_credential_name(name)
    is_hardcoded_string(value)
}

is_hardcoded_credential(name, value) {
    is_user_name(name)
    is_hardcoded_string(value)
    not regex.match(`(?i)(uid=|cn=|dc=|ou=)`, value.value)
}

is_hardcoded_credential(name, value) {
    is_standalone_key_field(name)
    is_hardcoded_string(value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_hardcoded_credential(var.name, var.value)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Sensitive variable should not contain literal string values. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_hardcoded_credential(attr.name, attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Sensitive attribute should not contain literal string values. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    pair.key.ir_type == "String"
    is_hardcoded_credential(pair.key.value, pair.value)
    result := {
        "type": "sec_hard_secr",
        "element": pair.key,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Sensitive key in nested structure should not contain literal string values. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, value])
    value.ir_type == "String"
    regex.match(`(?i)://[^:@\s]+:[^:@\s]+@`, value.value)
    result := {
        "type": "sec_hard_secr",
        "element": value,
        "path": parent.path,
        "description": "Use of hard-coded credentials in connection string. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, value])
    value.ir_type == "String"
    regex.match(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|-----BEGIN CERTIFICATE-----`, value.value)
    result := {
        "type": "sec_hard_secr",
        "element": value,
        "path": parent.path,
        "description": "Use of hard-coded cryptographic key material. (CWE-798)"
    }
}