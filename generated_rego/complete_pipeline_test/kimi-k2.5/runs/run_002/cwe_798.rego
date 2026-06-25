package glitch

import data.glitch_lib
import future.keywords.in

credential_exact_names := {
    "password", "secret", "secret_key", "api_key", "private_key", "certificate",
    "passphrase", "root_password", "admin_password", "sha512_password",
    "sha256_password", "md5_password", "password_digest", "keystore", "truststore",
    "truststore_password", "keystore_password", "key", "token", "auth_token",
    "access_key", "credential", "credentials", "rbd_secret_uuid", "username",
    "user", "admin_user", "root_user", "default_user", "service_account"
}

credential_suffixes := {"_password", "_secret", "_key", "_token", "_user", "_username", "_uuid"}

get_final_segment(name) = segment {
    parts := split(name, ".")
    count(parts) > 0
    segment := parts[minus(count(parts), 1)]
}

has_credential_keyword(name) {
    lower_name := lower(name)
    some kw in credential_exact_names
    kw == lower_name
} else {
    lower_name := lower(name)
    some suffix in credential_suffixes
    endswith(lower_name, suffix)
} else {
    lower_name := lower(name)
    contains(lower_name, "password")
} else {
    lower_name := lower(name)
    contains(lower_name, "secret")
} else {
    lower_name := lower(name)
    contains(lower_name, "_key")
} else {
    lower_name := lower(name)
    contains(lower_name, "_token")
}

is_credential_field(name) {
    lower(name) == credential_exact_names[_]
} else {
    lower_name := lower(name)
    some suffix in credential_suffixes
    endswith(lower_name, suffix)
} else {
    has_credential_keyword(name)
}

is_encoded_or_hash(str) {
    regex.match(`^(?:[A-Za-z0-9+/]{20,}={0,2})$`, str)
} else {
    regex.match(`^\$[0-9a-z]+\$`, str)
} else {
    regex.match(`^(?i)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`, str)
} else {
    regex.match(`^(?i)[a-f0-9]{32,}$`, str)
} else {
    count(str) >= 32
    regex.match(`^[A-Za-z0-9\-_]+$`, str)
}

is_placeholder(str) {
    lower_str := lower(str)
    placeholder_patterns := {"changeme", "default", "123456", "test", "admin123", "cassandra"}
    placeholder_patterns[lower_str]
}

is_secure_reference(str) {
    regex.match(`\$\{[a-zA-Z_]`, str)
} else {
    regex.match(`\$\$`, str)
} else {
    regex.match(`^\$::`, str)
} else {
    regex.match(`^\$[a-zA-Z_]`, str)
    not regex.match(`^\$\d`, str)
}

is_benign_admin_value(str) {
    lower_str := lower(str)
    benign_values := {"true", "false", "none", "null", "present", "absent"}
    benign_values[lower_str]
} else {
    lower_str := lower(str)
    str == ""
}

should_flag_credential_value(str) {
    is_encoded_or_hash(str)
} else {
    is_placeholder(str)
} else {
    count(str) > 0
    not is_secure_reference(str)
    not is_benign_admin_value(str)
}

check_leaf_key_value(key_node, value_node, parent) = result {
    key_node.ir_type == "String"
    value_node.ir_type == "String"
    is_credential_field(key_node.value)
    should_flag_credential_value(value_node.value)
    result := {
        "type": "sec_hard_secr",
        "element": key_node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid hard-coding credentials in Infrastructure as Code. Use secret management systems instead. (CWE-798)"
    }
}

scan_node(node, parent) = results {
    results := {r |
        node.ir_type == "Variable"
        is_credential_field(node.name)
        node.value.ir_type == "String"
        should_flag_credential_value(node.value.value)
        r := {
            "type": "sec_hard_secr",
            "element": node,
            "path": parent.path,
            "description": "Use of Hard-coded Credentials - Avoid hard-coding credentials in Infrastructure as Code. Use secret management systems instead. (CWE-798)"
        }
    }
} union {r |
    node.ir_type == "Attribute"
    is_credential_field(node.name)
    node.value.ir_type == "String"
    should_flag_credential_value(node.value.value)
    r := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid hard-coding credentials in Infrastructure as Code. Use secret management systems instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    result := scan_node(parent, parent)[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "UnitBlock"
    
    walk(node, [_, inner])
    result := scan_node(inner, parent)[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Hash"
    
    some key
    entry := node.value[key]
    result := check_leaf_key_value(entry.key, entry.value, parent)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Array"
    
    some idx
    entry := node.value[idx]
    result := check_leaf_key_value(entry.key, entry.value, parent)
}