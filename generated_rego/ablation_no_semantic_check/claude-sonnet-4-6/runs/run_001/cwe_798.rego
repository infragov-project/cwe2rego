package glitch

import data.glitch_lib

credential_field_pattern := "(?i)(password|passwd|secret|api_key|apikey|api_token|access_key|auth_token|access_token|bearer_token|private_key|ssh_private_key|rsa_private_key|encryption_key|signing_key|jwt_secret|client_secret|app_secret|db_password|database_password|secret_access_key|master_secret|admin_password|root_password|default_password|credential)"

is_hardcoded_string(value) {
    value.ir_type == "String"
    value.value != ""
    not regex.match(`\$\{[^}]+\}`, value.value)
    not regex.match(`\$\([^)]+\)`, value.value)
    not regex.match(`\{\{[^}]+\}\}`, value.value)
}

is_credential_field(name) {
    regex.match(credential_field_pattern, name)
}

contains_pem_block(value) {
    value.ir_type == "String"
    contains(value.value, "-----BEGIN")
}

contains_embedded_credentials(value) {
    value.ir_type == "String"
    regex.match(`(?i)[a-z][a-z0-9+\-.]*://[^:@\s/]+:[^@\s/]+@`, value.value)
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
        "description": "Use of hard-coded credentials - Credential-related attribute contains a hardcoded literal value instead of a reference to a secrets store. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    v := vars[_]

    is_credential_field(v.name)
    is_hardcoded_string(v.value)

    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credential-related variable contains a hardcoded literal value instead of a reference to a secrets store. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    contains_pem_block(attr.value)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Attribute contains an embedded cryptographic key or certificate as a literal PEM block. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    contains_embedded_credentials(attr.value)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Attribute contains a connection string with embedded username and password. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    v := vars[_]

    contains_pem_block(v.value)

    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Variable contains an embedded cryptographic key or certificate as a literal PEM block. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    v := vars[_]

    contains_embedded_credentials(v.value)

    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Variable contains a connection string with embedded username and password. (CWE-798)"
    }
}