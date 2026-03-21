package glitch

import data.glitch_lib

credential_name_pattern := "(?i)(password|passwd|pwd|secret|token|api_key|apikey|api_secret|app_key|app_secret|client_key|service_key|private_key|encryption_key|decryption_key|signing_key|hmac_key|connection_string|connectionstring|db_url|database_url|jdbc_url|dsn|mongo_uri|redis_url|amqp_url|broker_url|smtp_url|access_key_id|secret_access_key|client_secret|storage_account_key|sas_token|service_account_key|gcp_credentials|ssh_key|id_rsa|tls_key|ssl_key|ssl_cert|tls_cert|ca_cert|pem_key|credentials|basic_auth)"

pem_pattern := "(?si)-----BEGIN.*(PRIVATE KEY|CERTIFICATE)"

connection_string_pattern := "(?i)(mongodb|postgresql|postgres|mysql|redis|amqp|smtp|ftp|jdbc)://[^:@\\s]+:[^@\\s]+@"

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(credential_name_pattern, attr.name)
    is_hardcoded_string(attr.value)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    regex.match(credential_name_pattern, var.name)
    is_hardcoded_string(var.value)

    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match(pem_pattern, attr.value.value)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded cryptographic material - Private keys or certificates should not be embedded in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match(connection_string_pattern, attr.value.value)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded connection string with embedded credentials - Connection strings should not contain inline credentials. (CWE-798)"
    }
}