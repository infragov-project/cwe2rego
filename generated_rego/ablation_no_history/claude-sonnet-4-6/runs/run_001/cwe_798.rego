package glitch

import data.glitch_lib

is_credential_key(name) {
    regex.match(`(?i)(password|passwd|pwd|keystore_password|truststore_password|secret_key|secret_access_key|api_key|api_token|auth_token|access_token|private_key|encryption_key|signing_key|client_secret|oauth_secret|hmac_secret|jwt_secret|bind_password|master_password|bearer|credential|credentials|pem|token|keystore|truststore)`, name)
}

is_credential_key(name) {
    lower(name) == "key"
}

is_credential_key(name) {
    regex.match(`(?i)(^secret$|(^|[_.\-])secret$|(^|[_.\-])secret[_.\-](key|token|access|password|value))`, name)
}

is_credential_key(name) {
    regex.match(`(?i)((^|[_.\-])user$|(^|[_.\-])username$)`, name)
}

is_literal_secret(value) {
    value.ir_type == "String"
    value.value != ""
    not regex.match(`(?i)(vault|secretsmanager|parameter.store|keyvault|\$\{|\{\{|secretRef|data\.)`, value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_credential_key(v.name)
    is_literal_secret(v.value)
    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credential-related variables should not contain static literal values. Use a secret management system instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_credential_key(attr.name)
    is_literal_secret(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credential-related attribute fields should not contain static literal values. Use a secret management system instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.key.ir_type == "String"
    is_credential_key(node.key.value)
    is_literal_secret(node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credential-related hash entry should not contain static literal values. Use a secret management system instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(`-----BEGIN [A-Z ]+-----`, node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - PEM key material should not be embedded inline in IaC scripts. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match(`(?i)[a-z][a-z0-9+\-.]+://.+:.+@`, node.value)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Connection string contains embedded credentials in plain text. (CWE-798)"
    }
}