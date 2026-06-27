package glitch

import data.glitch_lib

credential_keywords := {"password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "access_key", "secret_key", "credentials", "auth_token", "bearer", "jwt", "private_key", "public_key", "ssh_key", "cert", "certificate", "key_pem", "key_data", "encryption_key", "decryption_key", "connection_string", "dsn", "jdbc_url", "database_url", "mongo_uri", "redis_url", "webhook_secret", "signing_secret", "hmac_key", "shared_secret", "client_secret", "key"}

high_entropy_pattern := "[A-Za-z0-9+/=]{16,}|[0-9a-fA-F]{16,}"

pem_pattern := "(?i)-----BEGIN\\s+(RSA|DSA|EC|OPENSSH)\\s+(PRIVATE|PUBLIC)\\s+KEY-----"

default_weak_values := {"admin", "password", "123456", "default", "root", "toor", "guest", "changeme", "change_me", "temp", "temporary"}

name_matches_credential(name) {
    lower_name := lower(name)
    some kw
    credential_keywords[kw]
    contains(lower_name, kw)
}

is_high_entropy_secret(str) {
    regex.match(high_entropy_pattern, str)
}

is_pem_structure(str) {
    regex.match(pem_pattern, str)
}

is_weak_default(str) {
    lower_val := lower(str)
    some w
    default_weak_values[w]
    lower_val == w
}

is_literal_string(value) {
    value.ir_type == "String"
    value.value != ""
}

references_secure_source(value) {
    value.ir_type == "FunctionCall"
    contains(lower(value.name), "data")
} else {
    value.ir_type == "FunctionCall"
    contains(lower(value.name), "vault")
} else {
    value.ir_type == "FunctionCall"
    contains(lower(value.name), "secret")
} else {
    value.ir_type == "FunctionCall"
    contains(lower(value.name), "var")
} else {
    value.ir_type == "FunctionCall"
    contains(lower(value.name), "lookup")
} else {
    value.ir_type == "MethodCall"
} else {
    value.ir_type == "VariableReference"
}

is_literal_credential_value(value) {
    is_literal_string(value)
    not references_secure_source(value)
}

is_leaf_value(v) {
    v.ir_type != "Hash"
    v.ir_type != "Array"
}

is_hash(h) {
    h.ir_type == "Hash"
}

hash_has_credential_pattern(pair) {
    pair.key.ir_type == "String"
    k := pair.key.value
    v := pair.value
    name_matches_credential(k)
    is_literal_credential_value(v)
} else {
    pair.key.ir_type == "String"
    k := pair.key.value
    v := pair.value
    name_matches_credential(k)
    is_literal_credential_value(v)
    is_high_entropy_secret(v.value)
} else {
    pair.key.ir_type == "String"
    k := pair.key.value
    v := pair.value
    name_matches_credential(k)
    is_literal_credential_value(v)
    is_pem_structure(v.value)
} else {
    pair.key.ir_type == "String"
    k := pair.key.value
    v := pair.value
    name_matches_credential(k)
    is_literal_credential_value(v)
    is_weak_default(v.value)
}

build_name(prefix, item_name) = result {
    prefix == ""
    result = item_name
} else {
    prefix != ""
    result = concat(".", [prefix, item_name])
}

hash_contains_credential_pattern(h) {
    is_hash(h)
    item := h.value[_]
    item.key.ir_type == "String"
    item_name := item.key.value
    full_name := build_name("", item_name)
    is_leaf_value(item.value)
    hash_has_credential_pattern({"key": {"ir_type": "String", "value": full_name}, "value": item.value})
}

hash_contains_credential_pattern(h) {
    is_hash(h)
    item := h.value[_]
    item.key.ir_type == "String"
    item_name := item.key.value
    full_name := build_name("", item_name)
    is_hash(item.value)
    items := item.value.value
    nested_item := items[_]
    nested_item.key.ir_type == "String"
    name_matches_credential(nested_item.key.value)
    is_literal_credential_value(nested_item.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    name := var.name
    value := var.value
    is_literal_credential_value(value)
    name_matches_credential(name)
    not is_false_positive(var, parent)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    value := var.value
    hash_contains_credential_pattern(value)
    not is_false_positive(var, parent)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    name := attr.name
    value := attr.value
    is_literal_credential_value(value)
    name_matches_credential(name)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    value := attr.value
    hash_contains_credential_pattern(value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. (CWE-798)"
    }
}

is_false_positive(var, parent) {
    name := var.name
    lower_name := lower(name)
    contains(lower_name, "admin")
    not contains(lower_name, "password")
    value := var.value
    is_literal_string(value)
    lower_val := lower(value.value)
    lower_val == "root"
}