package glitch

import data.glitch_lib

credential_keywords := [
    "passphrase",
    "activation_key",
    "activationkey",
    "api_secret",
    "api_token",
    "api_key",
    "access_key",
    "auth_token",
    "auth_key",
    "client_secret",
    "client_key",
    "consumer_key",
    "consumer_secret",
    "encryption_key",
    "master_key",
    "private_key",
    "secret_key",
    "signing_key",
    "credential",
    "password",
    "passwd",
    "secret",
    "token",
    "cred",
    "pass",
    "pwd",
    "pin",
    "key",
]

has_credential_keyword(name) {
    kw := credential_keywords[_]
    replaced := regex.replace(name, "([a-z])([A-Z])", "${1}_${2}")
    lower_name := lower(replaced)
    contains(lower_name, kw)
}

is_empty_or_null_value(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    has_credential_keyword(var.name)
    is_empty_or_null_value(var.value)

    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password or secret in configuration - Avoid using empty passwords or secrets in configuration files. (CWE-258)",
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    has_credential_keyword(attr.name)
    is_empty_or_null_value(attr.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password or secret in configuration - Avoid using empty passwords or secrets in configuration files. (CWE-258)",
    }
}