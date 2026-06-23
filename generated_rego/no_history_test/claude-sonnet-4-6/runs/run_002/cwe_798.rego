package glitch

import data.glitch_lib

sensitive_name_pattern := `(?i).*(password|passwd|pwd|secret|secret_key|secret_value|api_key|apikey|api_token|access_key|access_token|auth_token|auth_key|private_key|client_secret|master_password|admin_password|initial_password|bootstrap_password|maintenance_password|encryption_key|signing_key|ssl_key|tls_key|hmac_key|jwt_secret|bearer_token|oauth_token|webhook_secret|webhook_token|deploy_key|ssh_key|ssh_private_key|preshared_key|pre_shared_key|vpn_password|vpn_secret|database_url|db_url|connection_string|db_uri|dsn|service_account_key|subscription_key|storage_account_key|access_key_id|secret_access_key|refresh_token|registration_token|bootstrap_token|username|user|keystore|truststore|(?:^|[._-])key(?:[._-]|$)).*`

is_template_reference(str) {
    regex.match(`.*(\$\{[^}]+\}|\$\([^)]+\)|\{\{[^}]+\}\}|!Ref |!Sub ).*`, str)
}

is_file_path(str) {
    regex.match(`^(/|\.\.?/|[A-Za-z]:\\).*`, str)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
    not is_template_reference(value.value)
    not is_file_path(value.value)
}

is_credential_field(name) {
    regex.match(sensitive_name_pattern, name)
}

is_credential_field(name) {
    regex.match(`(?i)^key$`, name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_credential_field(attr.name)
    is_hardcoded_string(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Sensitive field contains a literal value instead of a secret manager reference. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_credential_field(var.name)
    is_hardcoded_string(var.value)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Sensitive variable contains a literal value instead of a secret manager reference. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    is_credential_field(entry.key.value)
    is_hardcoded_string(entry.value)
    result := {
        "type": "sec_hard_secr",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Sensitive field contains a literal value inside a nested structure. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(`(?i)-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----`, node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Embedded cryptographic key material detected. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(`.*://[^@\s]+:[^@\s]+@[^/\s]+.*`, node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Connection string with embedded credentials detected. (CWE-798)"
    }
}