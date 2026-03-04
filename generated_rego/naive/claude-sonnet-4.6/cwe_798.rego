package glitch

import data.glitch_lib

credential_field_pattern := "(?i)(password|passwd|passphrase|secret|api_key|apikey|api_secret|api_token|access_token|auth_token|bearer_token|refresh_token|access_key_id|secret_access_key|private_key|encryption_key|signing_key|rsa_key|ssh_key|ssl_cert|tls_cert|connection_string|connection_url|database_url|snmp_community|authentication_key|client_secret|shared_secret|username|admin_user|become_user|user|uid)"

exact_credential_fields := {
    "pwd", "pass", "token", "cert", "auth", "credentials",
    "access_key", "authorization", "certificate", "db_url", "jdbc_url",
    "community_string", "public_key"
}

is_credential_field_name(name) {
    regex.match(credential_field_pattern, name)
}

is_credential_field_name(name) {
    lower_name := lower(name)
    lower_name == exact_credential_fields[_]
}

is_hardcoded_string_value(value) {
    value.ir_type == "String"
    value.value != ""
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_credential_field_name(attr.name)
    is_hardcoded_string_value(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    is_credential_field_name(variable.name)
    is_hardcoded_string_value(variable.value)
    result := {
        "type": "sec_hard_secr",
        "element": variable,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    is_credential_field_name(entry.key.value)
    is_hardcoded_string_value(entry.value)
    result := {
        "type": "sec_hard_secr",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hardcoded in IaC scripts. (CWE-798)"
    }
}