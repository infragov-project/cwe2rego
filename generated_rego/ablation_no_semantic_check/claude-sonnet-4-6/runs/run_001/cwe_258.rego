package glitch

import data.glitch_lib

credential_name_pattern := "(?i)(password|passwd|pwd|pass|secret|token|api_key|access_key|private_key|credential|auth_pass|bind_pass|ldap_pass|admin_pass|root_pass|master_pass|keystore_pass|truststore_pass|smtp_pass|mail_pass|ftp_pass|ssh_pass|db_pass|database_pass|mysql_pass|postgres_pass|redis_pass|mongo_pass)"

connection_string_pattern := "(?i)(connection_?string|db_url|database_url|dsn|jdbc_url|odbc)"

is_credential_field(name) {
    regex.match(credential_name_pattern, name)
}

is_empty_value(value) {
    value.ir_type == "String"
    regex.match("^\\s*$", value.value)
}

is_empty_value(value) {
    value.ir_type == "Null"
}

is_empty_value(value) {
    value.ir_type == "Undef"
}

is_empty_connection_string(value) {
    value.ir_type == "String"
    regex.match("(?i)(pwd=;|password=;|://[^:@]*:@)", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    is_credential_field(attr.name)
    is_empty_value(attr.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration - Credential fields should not have empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    variable := vars[_]

    is_credential_field(variable.name)
    is_empty_value(variable.value)

    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration - Credential fields should not have empty or null values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match(connection_string_pattern, attr.name)
    is_empty_connection_string(attr.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in connection string - Connection strings should not have empty password segments. (CWE-258)"
    }
}