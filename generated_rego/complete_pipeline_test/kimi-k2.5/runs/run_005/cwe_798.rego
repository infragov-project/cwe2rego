package glitch

import data.glitch_lib

credential_full_keys := {
    "password", "passwd", "pwd", "secret", "secretkey", "secret_key",
    "token", "authtoken", "auth_token", "accesstoken", "access_token",
    "apikey", "api_key", "accesskey", "access_key", "privatekey", "private_key",
    "credential", "cred", "credentials",
    "sha512_password", "sha256_password", "md5_password",
    "keystore_password", "truststore_password"
}

credential_suffix_keys := {
    "_password", "_passwd", "_pwd", "_secret", "_secretkey", "_key",
    "_token", "_auth", "_credential", "_credentials"
}

credential_contains := {
    "password", "secret", "token", "key", "auth", "credential"
}

is_credential_key(key_str) {
    lower_key := lower(key_str)
    credential_full_keys[lower_key]
} else {
    lower_key := lower(key_str)
    some suffix
    credential_suffix_keys[suffix]
    endswith(lower_key, suffix)
} else {
    lower_key := lower(key_str)
    some indicator
    credential_contains[indicator]
    contains(lower_key, indicator)
}

is_base64_like(val) {
    regex.match("^[A-Za-z0-9+/]{10,}={0,2}$", val)
}

is_hash_like(val) {
    regex.match("^[0-9a-fA-F]{16,}$", val)
}

is_crypt_hash(val) {
    regex.match("^\\$[0-6]\\$[A-Za-z0-9./]{8,}\\$[A-Za-z0-9./]{22,}$", val)
}

is_jwt_like(val) {
    regex.match("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+$", val)
}

is_high_entropy(val) {
    count(val) >= 10
    regex.match("[^A-Za-z]", val)
}

looks_like_secret_value(val) {
    is_base64_like(val)
} else {
    is_hash_like(val)
} else {
    is_crypt_hash(val)
} else {
    is_jwt_like(val)
} else {
    is_high_entropy(val)
}

is_external_reference(val) {
    startswith(val, "{{")
} else {
    startswith(val, "${")
} else {
    startswith(val, "%{")
} else {
    startswith(val, "lookup(")
} else {
    startswith(val, "vault::")
} else {
    startswith(val, "hiera(")
} else {
    startswith(val, "data.")
} else {
    regex.match("\\$\\{.*\\}", val)
} else {
    regex.match("\\$\\w+", val)
}

is_file_path(val) {
    regex.match("^(/|\\.\\.?/|[A-Za-z]:\\|)", val)
} else {
    regex.match("\\.(yml|yaml|json|erb|epp|pem|key|crt|cert)$", lower(val))
}

is_config_value(val) {
    lower_val := lower(val)
    startswith(lower_val, "org.apache.")
} else {
    startswith(lower_val, "com.")
} else {
    startswith(lower_val, "io.")
} else {
    startswith(lower_val, "java.")
} else {
    startswith(lower_val, "sun.")
} else {
    startswith(lower_val, "javax.")
} else {
    startswith(lower_val, "'[")
} else {
    startswith(val, "[")
} else {
    regex.match("^[A-Z][a-z]+[A-Z]", val)
}

is_common_non_secret(val) {
    lower_val := lower(val)
    lower_val == "true"
} else {
    lower_val == "false"
} else {
    lower_val == "yes"
} else {
    lower_val == "no"
} else {
    lower_val == "null"
} else {
    lower_val == "none"
} else {
    val == ""
} else {
    regex.match("^[a-z]+$", val)
    count(val) <= 6
}

is_viable_credential_value(val) {
    looks_like_secret_value(val)
    not is_external_reference(val)
    not is_file_path(val)
    not is_config_value(val)
    not is_common_non_secret(val)
}

private_key_markers := {
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN ENCRYPTED PRIVATE KEY",
    "BEGIN DSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY"
}

embedded_credential_regex := "^[a-z]+://[^@/:]+:[^@/]+@"

detect_credential_pair(parent_path, key_str, val_node, path) = result {
    val_node.ir_type == "String"
    val := val_node.value
    is_credential_key(key_str)
    is_viable_credential_value(val)
    result := {
        "type": "sec_hard_secr",
        "element": val_node,
        "path": path,
        "description": "Use of Hard-coded Credentials - Detected hardcoded credential in configuration. (CWE-798)"
    }
}

walk_any_hash(node, path) = results {
    node.ir_type == "Hash"
    results := {r |
        some i
        item := node.value[i]
        item.key.ir_type == "String"
        key_str := item.key.value
        val_item := item.value
        r := detect_hash_recursive(item.key, val_item, key_str, path)
    }
}

detect_hash_recursive(key_node, val_node, key_str, path) = result {
    val_node.ir_type == "String"
    result := detect_credential_pair(key_str, key_str, val_node, path)
}

detect_hash_recursive(key_node, val_node, key_str, path) = result {
    val_node.ir_type == "Hash"
    inner := walk_any_hash(val_node, path)
    result := inner[_]
}

detect_hash_recursive(key_node, val_node, key_str, path) = result {
    val_node.ir_type == "Array"
    some i
    item := val_node.value[i]
    result := detect_hash_recursive(key_node, item, key_str, path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    is_credential_key(node.name)
    val_node := node.value
    val_node.ir_type == "String"
    val := val_node.value
    is_viable_credential_value(val)
    result := {
        "type": "sec_hard_secr",
        "element": val_node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Detected hardcoded credential in variable assignment. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "Hash"
    results := walk_any_hash(node.value, parent.path)
    result := results[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_credential_key(node.name)
    val_node := node.value
    val_node.ir_type == "String"
    val := val_node.value
    is_viable_credential_value(val)
    result := {
        "type": "sec_hard_secr",
        "element": val_node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Detected hardcoded credential in attribute definition. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "Hash"
    results := walk_any_hash(node.value, parent.path)
    result := results[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    val := node.value
    regex.match(embedded_credential_regex, val)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Detected embedded credentials in URL/connection string. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    val := node.value
    some marker
    private_key_markers[marker]
    contains(val, marker)
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Detected hardcoded private key material. (CWE-798)"
    }
}