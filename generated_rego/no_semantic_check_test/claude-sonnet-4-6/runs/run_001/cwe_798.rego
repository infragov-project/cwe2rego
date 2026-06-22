package glitch

import data.glitch_lib

sensitive_field_pattern := "(?i).*(password|passwd|pwd|secret|api_key|api_token|access_key|auth_token|bearer_token|private_key|encryption_key|signing_key|certificate|connection_string|database_url|db_url|dsn|snmp_password|community_string|client_secret|consumer_secret|oauth_token|ssh_private_key|pgp_key|service_account).*"

pem_pattern := "-----BEGIN .*(PRIVATE KEY|CERTIFICATE)-----"

connection_cred_pattern := "(?i)(password=|pwd=|passwd=|://[^:@ ]+:[^@/ ]+@)"

is_sensitive_name(name) {
    regex.match(sensitive_field_pattern, name)
}

is_literal_string(value) {
    value.ir_type == "String"
    value.value != ""
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_sensitive_name(attr.name)
    is_literal_string(attr.value)
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
    is_literal_string(var.value)
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
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match(pem_pattern, attr.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Inline cryptographic material (PEM key or certificate) detected. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "String"
    regex.match(pem_pattern, var.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Inline cryptographic material (PEM key or certificate) detected. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match(connection_cred_pattern, attr.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Connection string with embedded credentials detected. (CWE-798)"
    }
}