package glitch

import data.glitch_lib

credential_keywords := {"password", "pwd", "pass", "passwd", "secret", "auth_token", "access_token", "refresh_token", "bearer_token", "api_key", "apikey", "api_secret", "client_secret", "client_id", "private_key", "privatekey", "secret_key", "secretkey", "encryption_key", "decryption_key", "signing_key", "verification_key", "key_pair", "keystore_password", "truststore_password", "cert_password", "ssl_password", "tls_password", "ca_private_key", "db_password", "database_password", "root_password", "admin_password", "master_password", "replica_password", "service_principal_secret", "connection_string", "jdbc_password", "odbc_password", "ldap_password", "sha512_password", "sha256_password", "md5_password", "encrypted_password", "blowfish_secret", "default_password", "user_password", "key", "token", "keystore", "truststore", "cert", "certificate", "uuid", "user"}

is_credential_field(name) {
    lower_name := lower(name)
    credential_keywords[_] == lower_name
}

is_credential_field(name) {
    lower_name := lower(name)
    endswith(lower_name, "_password")
}

is_credential_field(name) {
    lower_name := lower(name)
    endswith(lower_name, "_secret")
}

is_credential_field(name) {
    lower_name := lower(name)
    endswith(lower_name, "_key")
}

is_credential_field(name) {
    lower_name := lower(name)
    endswith(lower_name, "_token")
}

is_credential_field(name) {
    lower_name := lower(name)
    startswith(lower_name, "secr")
}

is_credential_field(name) {
    lower_name := lower(name)
    contains(lower_name, "passwd")
}

is_credential_field(name) {
    lower_name := lower(name)
    contains(lower_name, "password")
}

is_credential_field(name) {
    lower_name := lower(name)
    contains(lower_name, "credential")
}

is_ignorable_value(val) {
    ignorable_patterns := {"changeme", "change_me", "changemerightnow", "example", "sample", "test_test", "xxx", "yyy", "zzz", "to_be_changed", "insert_here", "fill_me_in", "replace_me", "your_value_here", "enter_your", "configure_your", "set_your", "your_", "_here", "_placeholder", "_dummy", "null", "none", "nil", "undefined", "true", "false", "yes", "no", "on", "off", "enable", "disable"}
    lower_val := lower(val)
    ignorable_patterns[_] == lower_val
}

is_ignorable_value(val) {
    regex.match(`^\s*$`, val)
}

check_value_is_literal_credential(v) {
    v.ir_type == "String"
    count(v.value) > 0
    not is_ignorable_value(v.value)
}

extract_name_parts(name_str) = parts {
    parts := regex.split(`[\.\[\]'\"]+`, name_str)
}

any_name_part_matches_credential(name_str) {
    parts := extract_name_parts(name_str)
    part := parts[_]
    part != ""
    is_credential_field(part)
}

last_name_part_matches_credential(name_str) {
    parts := extract_name_parts(name_str)
    count(parts) > 0
    last_idx := count(parts) - 1
    last_part := parts[last_idx]
    last_part != ""
    is_credential_field(last_part)
}

get_path_for_report(node, parent_path) = path {
    path := parent_path
} else = path {
    node.ir_type == "String"
    path := node.value
} else = path {
    path := ""
}

collect_credential_from_hash(node, parent_path) = result {
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    key_str := entry.key.value
    is_credential_field(key_str)
    entry.value.ir_type == "String"
    val_node := entry.value
    count(val_node.value) > 0
    not is_ignorable_value(val_node.value)
    result := [key_str, val_node, key_str]
}

collect_credential_from_hash(node, parent_path) = result {
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.value.ir_type == "Hash"
    nested := collect_credential_from_hash(entry.value, parent_path)
    nested != []
    result := nested
}

collect_credential_from_hash(node, parent_path) = result {
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.value.ir_type == "Array"
    item := entry.value[_]
    item.ir_type == "Hash"
    nested := collect_credential_from_hash(item, parent_path)
    nested != []
    result := nested
}

collect_all_credential_locations(parent) = result {
    result := {[key_str, val_node, key_str] |
        walk(parent, [_, node])
        node.ir_type == "Hash"
        entry := node.value[_]
        entry.key.ir_type == "String"
        key_str := entry.key.value
        is_credential_field(key_str)
        entry.value.ir_type == "String"
        val_node := entry.value
        count(val_node.value) > 0
        not is_ignorable_value(val_node.value)
    }
}

Glitch_Analysis[result] {
    walk(input, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "String"
    val := node.value.value
    count(val) > 0
    not is_ignorable_value(val)
    any_name_part_matches_credential(node.name)
    result := {
        "type": "sec_hard_secr",
        "element": node.value,
        "path": node.name,
        "description": "Hard-coded credentials - Credentials should not be hard-coded in infrastructure configuration. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "String"
    val := node.value.value
    count(val) > 0
    not is_ignorable_value(val)
    any_name_part_matches_credential(node.name)
    result := {
        "type": "sec_hard_secr",
        "element": node.value,
        "path": node.name,
        "description": "Hard-coded credentials - Credentials should not be hard-coded in infrastructure configuration. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, node])
    node.ir_type == "KeyValue"
    node.value.ir_type == "String"
    val := node.value.value
    count(val) > 0
    not is_ignorable_value(val)
    is_credential_field(node.name)
    result := {
        "type": "sec_hard_secr",
        "element": node.value,
        "path": node.name,
        "description": "Hard-coded credentials - Credentials should not be hard-coded in infrastructure configuration. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    creds := collect_all_credential_locations(parent)
    [key_str, val_node, _] := creds
    result := {
        "type": "sec_hard_secr",
        "element": val_node,
        "path": key_str,
        "description": "Hard-coded credentials - Credentials should not be hard-coded in infrastructure configuration. (CWE-798)"
    }
}