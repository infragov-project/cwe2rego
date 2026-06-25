package glitch

import data.glitch_lib

is_credential_field_name(name) {
    regex.match(`(?i).*(password|passwd|secret|api_key|api_token|api_secret|access_key|secret_key|auth_token|auth_password|private_key|client_secret|db_pass|database_password|bearer_token|encryption_key|master_key|master_password|webhook_secret|cert_body|tls_cert|connection_string|database_url|mongo_uri|redis_url|oauth_token|refresh_token|session_token|hmac_key|ssh_private_key).*`, name)
}

is_literal_credential_value(value) {
    value.ir_type == "String"
    value.value != ""
    not regex.match(`^\$\{`, value.value)
    not regex.match(`^\{\{`, value.value)
    not regex.match(`^\$\(`, value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_credential_field_name(attr.name)
    is_literal_credential_value(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be stored as literal values in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_credential_field_name(v.name)
    is_literal_credential_value(v.value)
    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be stored as literal values in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match(`(?i)://[^:@\s]+:[^@\s]+@`, attr.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials in connection string - Connection strings should not embed credentials inline. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match(`-----BEGIN`, attr.value.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded cryptographic key material - Cryptographic keys should not be stored as literal values. (CWE-798)"
    }
}