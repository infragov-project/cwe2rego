package glitch

import data.glitch_lib

credential_keywords := ["password", "passwd", "pwd", "secret", "credentials", "auth_token", "api_key", "apikey", "access_key", "secret_key", "private_key", "account_key", "username", "user_name", "login", "root_user", "service_account", "default_user", "connection_string", "conn_string", "dsn", "certificate", "cert", "pem", "rsa_key", "dsa_key", "ecdsa_key", "ed25519_key", "tls_key", "ssl_key", "ssh_key", "recovery_password", "maintenance_password", "diagnostic_password", "initial_password", "first_boot_password", "setup_password", "sha512_password", "key"]

default_credentials := ["admin", "password", "root", "default", "123456", "changeme", "guest", "user", "test", "demo", "example", "sample", "sensu", "redhat", "administrator"]

is_credential_key(name) {
    lower_name := lower(name)
    some kw
    credential_keywords[kw]
    contains(lower_name, kw)
}

is_safe_key_context(name) {
    lowered := lower(name)
    contains(lowered, "_user")
    not contains(lowered, "password")
    not contains(lowered, "secret")
    not contains(lowered, "key")
}

is_safe_key_context(name) {
    lowered := lower(name)
    startswith(lowered, "secret_")
    not contains(lowered, "password")
    not contains(lowered, "key")
}

contains_default_credential(value) {
    lower_val := lower(value)
    some dc
    default_credentials[dc]
    contains(lower_val, dc)
}

is_string_literal(node) {
    node.ir_type == "String"
    count(node.value) > 0
    not regex.match("^\\$\\{.*\\}$", node.value)
    not regex.match("^(vault|data|var|module|secret|keyvault|azuread|aws_secretsmanager|random_password)\\.", node.value)
}

is_private_key_material(value) {
    regex.match("^\\s*-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?(PRIVATE KEY|CERTIFICATE)-----", value)
}

is_connection_string_with_auth(value) {
    regex.match("(?i)[a-z]+://[^/]+:[^@]+@", value)
}

is_base64_like(value) {
    regex.match("^[A-Za-z0-9+/]{16,}={0,2}$", value)
}

is_password_hash(value) {
    regex.match("^\\$[0-9a-zA-Z]+\\$", value)
}

is_hex_guid_like(value) {
    regex.match("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", value)
}

any_is_suspicious_or_default(val) {
    is_base64_like(val)
}

any_is_suspicious_or_default(val) {
    is_private_key_material(val)
}

any_is_suspicious_or_default(val) {
    is_connection_string_with_auth(val)
}

any_is_suspicious_or_default(val) {
    is_password_hash(val)
}

any_is_suspicious_or_default(val) {
    contains_default_credential(val)
}

is_complex_value(node) {
    node.ir_type == "Hash"
}

is_complex_value(node) {
    node.ir_type == "Array"
}

find_credential_in_nested(node, found_key, found_value) {
    node.ir_type == "Hash"
    item := node.value[_]
    item.key.ir_type == "String"
    key_name := item.key.value
    is_credential_key(key_name)
    not is_safe_key_context(key_name)
    item.value.ir_type == "String"
    is_string_literal(item.value)
    found_key = key_name
    found_value = item.value
}

find_credential_in_nested(node, found_key, found_value) {
    node.ir_type == "Hash"
    item := node.value[_]
    inner := item.value
    is_complex_value(inner)
    find_credential_in_nested(inner, found_key, found_value)
}

find_credential_in_nested(node, found_key, found_value) {
    node.ir_type == "Array"
    elem := node.value[_]
    is_complex_value(elem)
    find_credential_in_nested(elem, found_key, found_value)
}

all_variables_deep(parent) = vars {
    vars := {v |
        walk(parent, [_, node])
        node.ir_type == "Variable"
        v := node
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := all_variables_deep(parent)
    var := vars[_]
    
    is_credential_key(var.name)
    not is_safe_key_context(var.name)
    var.value.ir_type == "String"
    is_string_literal(var.value)
    any_is_suspicious_or_default(var.value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := all_variables_deep(parent)
    var := vars[_]
    
    is_complex_value(var.value)
    find_credential_in_nested(var.value, found_key, found_value)
    any_is_suspicious_or_default(found_value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": found_value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    is_credential_key(attr.name)
    not is_safe_key_context(attr.name)
    attr.value.ir_type == "String"
    is_string_literal(attr.value)
    any_is_suspicious_or_default(attr.value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr.value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    is_complex_value(attr.value)
    find_credential_in_nested(attr.value, found_key, found_value)
    any_is_suspicious_or_default(found_value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": found_value,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}