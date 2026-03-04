package glitch

import data.glitch_lib

is_credential_field(name) {
    regex.match("(?i)^(password|passwd|pwd|pass|passphrase|secret|secret_key|secret_value|client_secret|admin_password|root_password|master_password|superuser_password|bootstrap_password|initial_password|default_password|ldap_password|ldap_bind_password|smtp_password|mail_password|proxy_password|service_password|app_password|ftp_password|ssh_password|db_password|database_password|mysql_root_password|postgres_password|redis_password|mongo_password|api_secret|oauth_secret|token_password|bearer_token|auth_token)$", name)
}

is_credential_field(name) {
    regex.match("(?i).*(password|passwd|passphrase|secret|credential).*", name)
}

is_hardcoded_string(value) {
    value.ir_type == "String"
    count(value.value) > 0
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    is_credential_field(attr.name)
    is_hardcoded_string(attr.value)

    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Credential field contains a literal string value. (CWE-259)"
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
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password in variable - Variable containing credentials has a literal string value. (CWE-259)"
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
    count(entry.value.value) > 0

    result := {
        "type": "sec_hard_pass",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded password in hash - Credential field contains a literal string value. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match("(?i)^(connection_string|database_url|db_url|dsn|jdbc_url|connection_url)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i).*(password=|pwd=|passwd=|credentials=)[^;\\s].*", attr.value.value)

    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password in connection string - Connection string contains embedded credentials. (CWE-259)"
    }
}