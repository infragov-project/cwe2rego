package glitch

import data.glitch_lib

exact_credential_keywords := {"user", "username", "key"}

substring_credential_keywords := {
    "password", "passwd", "passphrase", "secret", "token", "bearer",
    "api_key", "access_key", "secret_key", "auth_token", "credential",
    "private_key", "encryption_key", "signing_key", "master_key",
    "truststore", "keystore"
}

is_variable_reference(value) {
    regex.match(`\$\{`, value)
}

is_variable_reference(value) {
    regex.match(`\{\{`, value)
}

is_secret_management_ref(value) {
    regex.match(`(?i)(vault|secret[_-]?manager|key[_-]?vault|arn:|ssm:)`, value)
}

is_non_secret_value(value) {
    regex.match(`^(/|\./|~/)`, value)
}

is_non_secret_value(value) {
    regex.match(`(?i)^(cn|uid|dc|ou)=`, value)
}

is_non_secret_value(value) {
    regex.match(`(?i)^ldaps?://`, value)
}

is_non_secret_value(value) {
    regex.match(`(?i)^(true|false|nil|null|none|undefined)$`, value)
}

is_non_secret_value(value) {
    value == ""
}

get_leaf_name(name) = leaf {
    regex.match(`\[`, name)
    matches := regex.find_n(`'([^']+)'`, name, -1)
    count(matches) > 0
    last_match := matches[count(matches) - 1]
    trimmed := trim_prefix(last_match, "'")
    leaf := trim_suffix(trimmed, "'")
}

get_leaf_name(name) = leaf {
    not regex.match(`\[`, name)
    contains(name, ".")
    parts := split(name, ".")
    leaf := parts[count(parts) - 1]
}

get_leaf_name(name) = leaf {
    not regex.match(`\[`, name)
    not contains(name, ".")
    leaf := name
}

has_credential_keyword(name) {
    leaf := get_leaf_name(name)
    lower(leaf) == exact_credential_keywords[_]
}

has_credential_keyword(name) {
    leaf := get_leaf_name(name)
    contains(lower(leaf), substring_credential_keywords[_])
}

check_credential_value(val) {
    val.ir_type == "String"
    val.value != ""
    not is_variable_reference(val.value)
    not is_non_secret_value(val.value)
    not is_secret_management_ref(val.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    has_credential_keyword(var.name)
    check_credential_value(var.value)

    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Hard-coded credential detected in variable - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    walk(var.value, [_, hash_node])
    hash_node.ir_type == "Hash"
    kv := hash_node.value[_]
    kv.key.ir_type == "String"
    has_credential_keyword(kv.key.value)
    check_credential_value(kv.value)

    result := {
        "type": "sec_hard_secr",
        "element": kv,
        "path": parent.path,
        "description": "Hard-coded credential detected in nested hash - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    has_credential_keyword(attr.name)
    check_credential_value(attr.value)

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential detected in attribute - Avoid using hard-coded credentials. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    walk(attr.value, [_, hash_node])
    hash_node.ir_type == "Hash"
    kv := hash_node.value[_]
    kv.key.ir_type == "String"
    has_credential_keyword(kv.key.value)
    check_credential_value(kv.value)

    result := {
        "type": "sec_hard_secr",
        "element": kv,
        "path": parent.path,
        "description": "Hard-coded credential detected in nested attribute hash - Avoid using hard-coded credentials. (CWE-798)"
    }
}