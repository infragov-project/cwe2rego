package glitch

import data.glitch_lib

password_name_pattern := "(?i).*(password|passwd|passphrase|_pass|_pwd|pre_shared_key|preshared_key|shared_secret|enable_secret|tacacs_key|radius_secret|ike_psk|keystore_pass|truststore_pass|ssl_pass|tls_pass).*"

connection_field_pattern := "(?i).*(connection_string|connection_url|database_url|db_url|jdbc_url|dsn).*"

embedded_cred_pattern := "(?i).*(password=|passwd=|pwd=|pass=).+"

is_hardcoded_nonempty_string(value) {
    value.ir_type == "String"
    value.value != ""
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(password_name_pattern, attr.name)
    is_hardcoded_nonempty_string(attr.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hardcoded as literal values in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    regex.match(password_name_pattern, var.name)
    is_hardcoded_nonempty_string(var.value)
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password - Credentials should not be hardcoded as literal values in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(connection_field_pattern, attr.name)
    is_hardcoded_nonempty_string(attr.value)
    regex.match(embedded_cred_pattern, attr.value.value)
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password in connection string - Connection strings should not embed credentials as literal values. (CWE-259)"
    }
}