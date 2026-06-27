package glitch

import data.glitch_lib

credential_keywords := {"password", "passwd", "pwd", "secret", "secret_key", "access_key", "api_key", "api_secret", "auth_token", "bearer_token", "private_key", "client_secret", "connection_string", "encryption_key", "hmac_key", "aes_key", "signing_key", "master_key", "kms_key_id", "tls_key", "key_pem", "cert_pem", "ca_cert", "pre_shared_key", "preshared_key", "psk", "shared_key", "vpn_key", "admin_pass", "admin_password", "root_pass", "root_password", "default_password", "db_password", "database_password", "service_principal", "tenant_id", "subscription_id", "account_id", "session_token", "registry_password", "docker_config", "basic_auth", "htpasswd", "dockerhub_token", "vpn_shared_key", "ipsec_secret"}

password_hash_patterns := {"sha512_password", "pbkdf2_password", "md5_password", "sha256_password"}

is_literal_string_value(value) {
    value.ir_type == "String"
    value.value != ""
    not looks_like_reference(value.value)
}

looks_like_reference(v) {
    regex.match("(?i).*vault.*", v)
}

looks_like_reference(v) {
    regex.match("(?i).*secret_.*", v)
}

looks_like_reference(v) {
    regex.match("(?i).*random_.*", v)
}

looks_like_reference(v) {
    regex.match("(?i).*uuid.*", v)
}

looks_like_reference(v) {
    regex.match("(?i).*timestamp.*", v)
}

looks_like_reference(v) {
    regex.match("\\{\\{.*}}", v)
}

looks_like_reference(v) {
    regex.match("\\$\\{.*}", v)
}

looks_like_reference(v) {
    regex.match("^\\s*data\\.", v)
}

looks_like_reference(v) {
    regex.match("^\\s*var\\.", v)
}

is_credential_field_name(name) {
    kw := credential_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [kw]), name)
}

is_credential_field_name(name) {
    pw := password_hash_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [pw]), name)
}

is_key_field(name) {
    lower(name) == "key"
}

is_high_entropy_or_hash(value) {
    regex.match("^[A-Za-z0-9+/]{20,}={0,2}$", value)
}

is_high_entropy_or_hash(value) {
    regex.match("^[0-9a-fA-F]{32,}$", value)
}

is_high_entropy_or_hash(value) {
    regex.match("^\\$[0-9a-zA-Z]+\\$", value)
}

is_high_entropy_or_hash(value) {
    regex.match("^\\$6\\$", value)
}

check_value_for_credential(value) {
    is_literal_string_value(value)
}

check_value_for_credential(value) {
    value.ir_type == "String"
    is_high_entropy_or_hash(value.value)
}

walk_hash_for_credential(node) = found {
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    child_key := entry.key.value
    is_credential_field_name(child_key)
    check_value_for_credential(entry.value)
    found := entry.value
}

walk_hash_for_credential(node) = found {
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    child_key := entry.key.value
    is_key_field(child_key)
    is_credential_field_name(child_key)
    check_value_for_credential(entry.value)
    found := entry.value
}

walk_hash_for_credential(node) = found {
    node.ir_type == "Hash"
    entry := node.value[_]
    found := walk_hash_for_credential(entry.value)
}

walk_hash_for_credential(node) = found {
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.value.ir_type == "Array"
    elem := entry.value.value[_]
    found := walk_hash_for_credential(elem)
}

check_any_value_for_credential(value) {
    value.ir_type == "String"
    check_value_for_credential(value)
}

check_any_value_for_credential(value) {
    value.ir_type == "Hash"
    walk_hash_for_credential(value)
}

extract_credential_from_any(value) = found {
    value.ir_type == "String"
    check_value_for_credential(value)
    found := value
}

extract_credential_from_any(value) = found {
    value.ir_type == "Hash"
    found := walk_hash_for_credential(value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := parent.variables[_]
    is_credential_field_name(var.name)
    check_value_for_credential(var.value)
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. Use external secret management instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := parent.variables[_]
    check_any_value_for_credential(var.value)
    cred_elem := extract_credential_from_any(var.value)
    not is_credential_field_name(var.name)
    result := {
        "type": "sec_hard_secr",
        "element": cred_elem,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. Use external secret management instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    is_credential_field_name(attr.name)
    check_value_for_credential(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. Use external secret management instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    check_any_value_for_credential(attr.value)
    cred_elem := extract_credential_from_any(attr.value)
    not is_credential_field_name(attr.name)
    result := {
        "type": "sec_hard_secr",
        "element": cred_elem,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. Use external secret management instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := parent.attributes[_]
    is_credential_field_name(attr.name)
    check_value_for_credential(attr.value)
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. Use external secret management instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := parent.attributes[_]
    check_any_value_for_credential(attr.value)
    cred_elem := extract_credential_from_any(attr.value)
    not is_credential_field_name(attr.name)
    result := {
        "type": "sec_hard_secr",
        "element": cred_elem,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Credentials should not be hard-coded in configuration files. Use external secret management instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    lower(attr.name) == "disable_password_authentication"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Password authentication enabled - disable_password_authentication is set to false, indicating reliance on password-based authentication. Consider using key-based authentication instead. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    lower(attr.name) == "force_password_change"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Password change not forced - force_password_change is set to false, allowing initial passwords to persist. (CWE-798)"
    }
}