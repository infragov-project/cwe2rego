package glitch

import data.glitch_lib

password_field_pattern := "(?i).*(password|passwd|passphrase|secret|credential|keystore_pass|truststore_pass|ssl_pass|tls_pass|proxy_pass|smtp_pass|mail_pass|webhook_secret|key_pass|cert_pass|api_key|auth_token|bind_pass|pfx_pass|p12_pass|account_pass|initial_pass|admin_pass|root_pass|db_pass|database_pass|master_pass).*"

connection_field_pattern := "(?i).*(connection_string|connection_url|datasource_url|db_url|jdbc_url|dsn|uri|endpoint).*"

interpolation_pattern := "(\\$\\{|\\$\\(|\\{\\{|var\\.|<%=|\\$[A-Za-z_])"

is_literal_string(value) {
    value.ir_type == "String"
    value.value != ""
    not regex.match(interpolation_pattern, value.value)
}

has_embedded_credentials(value) {
    value.ir_type == "String"
    regex.match("(?i)(pwd=[^&\\s]+|password=[^&\\s]+|://[^:@/\\s]+:[^@/\\s]+@)", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(password_field_pattern, attr.name)
    is_literal_string(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords should not be hard-coded in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    variable := vars[_]
    regex.match(password_field_pattern, variable.name)
    is_literal_string(variable.value)
    result := {
        "type": "sec_hard_pass",
        "element": variable,
        "path": parent.path,
        "description": "Use of hard-coded password - Passwords should not be hard-coded in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(connection_field_pattern, attr.name)
    has_embedded_credentials(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password in connection string - Connection strings should not embed credentials. (CWE-259)"
    }
}