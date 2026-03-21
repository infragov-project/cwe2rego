package glitch

import data.glitch_lib

weak_algo_tokens := {"des", "3des", "rc2", "rc4", "blowfish", "idea", "seed", "md2", "md4", "md5", "md5crypt", "sha1", "sha-1", "sha_1", "sha1crypt", "xor", "base64", "legacy"}
weak_cipher_tokens := {"rc4", "3des", "des", "null", "export", "anull", "md5", "sha1", "sha-1", "sha_1", "low", "legacy"}

algo_key_tokens := {"encryption", "encrypt", "algorithm", "cipher", "crypto", "hash", "digest", "signature", "sse"}
password_key_tokens := {"password", "passwd", "passphrase", "secret", "credential", "credentials"}

weak_tls_regex := "(?i).*(sslv2|sslv3|ssl2|ssl3|tls1\\.0|tls1\\.1|tlsv1\\.0|tlsv1\\.1).*"

valid_parent[parent] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
}

kv_pairs[parent][kv] {
    valid_parent[parent]
    attrs := glitch_lib.all_attributes(parent)
    a := attrs[_]
    kv := {"name": a.name, "value": a.value, "element": a}
}

kv_pairs[parent][kv] {
    valid_parent[parent]
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    kv := {"name": v.name, "value": v.value, "element": v}
}

kv_pairs[parent][kv] {
    valid_parent[parent]
    walk(parent, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    key := entry.key
    key.ir_type == "String"
    kv := {"name": key.value, "value": entry.value, "element": entry.value}
}

kv_pairs[parent][kv] {
    valid_parent[parent]
    walk(parent, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    key := entry.key
    key.ir_type == "VariableReference"
    kv := {"name": key.value, "value": entry.value, "element": entry.value}
}

name_has_token(name, token) {
    pattern := sprintf("(?i)(^|[^a-z0-9])%s($|[^a-z0-9])", [token])
    regex.match(pattern, name)
}

name_has_any_token(name, tokens) {
    t := tokens[_]
    name_has_token(name, t)
}

string_has_token(str, token) {
    pattern := sprintf("(?i)(^|[^a-z0-9])%s($|[^a-z0-9])", [token])
    regex.match(pattern, str)
}

value_has_token(value, token) {
    walk(value, [_, n])
    n.ir_type == "String"
    string_has_token(n.value, token)
}

value_has_token(value, token) {
    walk(value, [_, n])
    n.ir_type == "VariableReference"
    string_has_token(n.value, token)
}

value_has_any_token(value, tokens) {
    t := tokens[_]
    value_has_token(value, t)
}

value_matches_regex(value, pattern) {
    walk(value, [_, n])
    n.ir_type == "String"
    regex.match(pattern, n.value)
}

value_matches_regex(value, pattern) {
    walk(value, [_, n])
    n.ir_type == "VariableReference"
    regex.match(pattern, n.value)
}

value_truthy(value) {
    walk(value, [_, n])
    n.ir_type == "Boolean"
    n.value == true
}

value_truthy(value) {
    walk(value, [_, n])
    n.ir_type == "String"
    regex.match("(?i)^(true|yes|1|on|enabled)$", n.value)
}

value_truthy(value) {
    walk(value, [_, n])
    n.ir_type == "VariableReference"
    regex.match("(?i)^(true|yes|1|on|enabled)$", n.value)
}

value_truthy(value) {
    walk(value, [_, n])
    n.ir_type == "Integer"
    n.value == 1
}

static_value(value) {
    walk(value, [_, n])
    n.ir_type == "String"
    regex.match("(?i).*(static|fixed|constant).*", n.value)
}

numeric_value(value, num) {
    walk(value, [_, n])
    n.ir_type == "Integer"
    num := n.value
}

numeric_value(value, num) {
    walk(value, [_, n])
    n.ir_type == "Float"
    num := n.value
}

numeric_value(value, num) {
    walk(value, [_, n])
    n.ir_type == "String"
    regex.match("^[0-9]+$", n.value)
    num := to_number(n.value)
}

is_algo_key(name) {
    name_has_any_token(name, algo_key_tokens)
}

is_password_key(name) {
    name_has_any_token(name, password_key_tokens)
}

is_cipher_key(name) {
    name_has_token(name, "cipher")
}

is_cipher_key(name) {
    name_has_token(name, "ciphers")
}

is_cipher_key(name) {
    name_has_token(name, "ssl")
    name_has_token(name, "policy")
}

is_tls_key(name) {
    name_has_token(name, "tls")
}

is_tls_key(name) {
    name_has_token(name, "ssl")
}

is_tls_key(name) {
    name_has_token(name, "protocol")
}

is_tls_key(name) {
    name_has_token(name, "protocols")
}

is_mode_key(name) {
    name_has_token(name, "mode")
    name_has_token(name, "cipher")
}

is_mode_key(name) {
    name_has_token(name, "mode")
    name_has_token(name, "block")
}

is_mode_key(name) {
    name_has_token(name, "mode")
    name_has_token(name, "encryption")
}

is_iv_param_name(name) {
    name_has_token(name, "iv")
}

is_iv_param_name(name) {
    name_has_token(name, "nonce")
}

is_iv_param_name(name) {
    name_has_token(name, "salt")
    not name_has_token(name, "size")
    not name_has_token(name, "length")
}

is_legacy_flag(name) {
    name_has_token(name, "legacy")
}

is_legacy_flag(name) {
    name_has_token(name, "compatibility")
}

is_legacy_flag(name) {
    name_has_token(name, "weak")
    name_has_token(name, "cipher")
}

is_generic_keysize(name) {
    regex.match("(?i)(^|[^a-z0-9])key[_-]?(size|length|bits|strength)($|[^a-z0-9])", name)
}

is_rsa_keysize(name) {
    regex.match("(?i)(^|[^a-z0-9])rsa[_-]?(bits|size|length)($|[^a-z0-9])", name)
}

is_dsa_keysize(name) {
    regex.match("(?i)(^|[^a-z0-9])dsa[_-]?(bits|size|length)($|[^a-z0-9])", name)
}

is_modulus_keysize(name) {
    regex.match("(?i)(^|[^a-z0-9])modulus[_-]?(bits|length)($|[^a-z0-9])", name)
}

is_dh_keysize(name) {
    regex.match("(?i)(^|[^a-z0-9])dh[_-]?(group|bits|length)($|[^a-z0-9])", name)
}

is_ecc_keysize(name) {
    regex.match("(?i)(^|[^a-z0-9])ecc[_-]?(curve|bits|length)($|[^a-z0-9])", name)
}

is_keysize_name(name) {
    is_generic_keysize(name)
} else {
    is_rsa_keysize(name)
} else {
    is_dsa_keysize(name)
} else {
    is_modulus_keysize(name)
} else {
    is_dh_keysize(name)
} else {
    is_ecc_keysize(name)
}

weak_keysize(name, num) {
    is_ecc_keysize(name)
    num < 256
}

weak_keysize(name, num) {
    is_rsa_keysize(name)
    num < 2048
}

weak_keysize(name, num) {
    is_dsa_keysize(name)
    num < 2048
}

weak_keysize(name, num) {
    is_modulus_keysize(name)
    num < 2048
}

weak_keysize(name, num) {
    is_dh_keysize(name)
    num < 2048
}

weak_keysize(name, num) {
    is_generic_keysize(name)
    not is_rsa_keysize(name)
    not is_dsa_keysize(name)
    not is_modulus_keysize(name)
    not is_dh_keysize(name)
    not is_ecc_keysize(name)
    num < 128
}

weak_algo_value(value) {
    value_has_any_token(value, weak_algo_tokens)
}

weak_cipher_value(value) {
    value_has_any_token(value, weak_cipher_tokens)
}

weak_algo_in_name(name) {
    name_has_any_token(name, weak_algo_tokens)
}

Glitch_Analysis[result] {
    kv_pairs[parent][kv]
    name := kv.name
    value := kv.value
    element := kv.element
    is_algo_key(name)
    weak_algo_value(value)
    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Weak or deprecated encryption algorithm specified. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    kv_pairs[parent][kv]
    name := kv.name
    value := kv.value
    element := kv.element
    is_password_key(name)
    weak_algo_value(value)
    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Weak password hashing or encryption algorithm detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    kv_pairs[parent][kv]
    name := kv.name
    element := kv.element
    is_password_key(name)
    weak_algo_in_name(name)
    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Weak password hashing or encryption algorithm indicated by name. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    kv_pairs[parent][kv]
    name := kv.name
    value := kv.value
    element := kv.element
    is_keysize_name(name)
    numeric_value(value, num)
    weak_keysize(name, num)
    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Insufficient key length or weak key specification. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    kv_pairs[parent][kv]
    name := kv.name
    value := kv.value
    element := kv.element
    is_tls_key(name)
    value_matches_regex(value, weak_tls_regex)
    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Outdated TLS/SSL protocol version allowed. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    kv_pairs[parent][kv]
    name := kv.name
    value := kv.value
    element := kv.element
    is_cipher_key(name)
    weak_cipher_value(value)
    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Weak cipher suites allowed. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    kv_pairs[parent][kv]
    name := kv.name
    value := kv.value
    element := kv.element
    is_mode_key(name)
    value_has_token(value, "ecb")
    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Insecure encryption mode detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    kv_pairs[parent][kv]
    name := kv.name
    value := kv.value
    element := kv.element
    is_iv_param_name(name)
    static_value(value)
    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Static IV/nonce/salt detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    kv_pairs[parent][kv]
    name := kv.name
    value := kv.value
    element := kv.element
    is_legacy_flag(name)
    value_truthy(value)
    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Legacy or weak encryption compatibility enabled. (CWE-326)"
    }
}