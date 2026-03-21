package glitch

import data.glitch_lib

weak_description := "Inadequate encryption strength - Weak cryptographic configuration detected. (CWE-326)"

algorithm_fields := {"algorithm", "cipher", "encryption_type", "encryption_algorithm", "encryption", "encrypt", "crypto_algorithm", "key_algorithm", "cipher_algorithm"}
protocol_fields := {"protocol", "ssl_protocol", "tls_version", "min_protocol_version", "max_protocol_version", "ssl_version", "tls_protocol", "ssl_protocols", "tls_protocols", "security_policy", "ssl_policy"}
cipher_fields := {"cipher_suites", "cipher_suite", "cipher", "ciphers", "allowed_ciphers", "cipher_list", "ssl_ciphers", "tls_ciphers", "ssl_policy", "security_policy"}
keysize_fields := {"key_size", "key_length", "keysize", "keylength", "key_bits", "rsa_bits", "dh_group", "dh_group_size", "dh_size", "curve", "key_spec", "key_strength", "bit_length", "bits"}
mode_fields := {"mode", "block_mode", "cipher_mode", "encryption_mode", "crypto_mode", "chaining_mode", "blockmode"}
legacy_flag_fields := {"allow_weak", "enable_legacy", "compatibility", "disable_strong", "fallback", "allow_downgrade", "legacy"}

weak_algo_pattern := "(?i)(^|[^a-z0-9])(des|3des|rc4|rc2|idea|blowfish|seed|xor|rot13|null|export)([^a-z0-9]|$)"
weak_protocol_pattern := "(?i)(^|[^a-z0-9])(sslv2|sslv3|ssl2|ssl3|tls1\\.0|tls1\\.1|tlsv1\\.0|tlsv1\\.1|tls1_0|tls1_1|tlsv1_0|tlsv1_1|tls-1-0|tls-1-1|tlsv1-0|tlsv1-1)([^a-z0-9]|$)"
weak_cipher_patterns := {
    "(?i)(^|[^a-z0-9])(rc4|des|3des|md5|sha1|sha-1|null|export)([^a-z0-9]|$)",
    "(?i)_SHA([^0-9]|$)"
}
weak_mode_pattern := "(?i)(^|[^a-z0-9])ecb([^a-z0-9]|$)"

weak_sym_sizes := {40, 56, 64, 80, 112, 128}
weak_asym_sizes := {1024, 1536}
weak_keysize_tokens := {"40", "56", "64", "80", "112", "128", "1024", "1536", "160", "192"}

field_match(name, fields) {
    f := fields[_]
    regex.match(sprintf("(?i)(^|[^a-z0-9])%s([^a-z0-9]|$)", [f]), name)
}

all_kv_pairs(node) = pairs {
    attrs := glitch_lib.all_attributes(node)
    vars := glitch_lib.all_variables(node)

    attr_pairs := {{"name": a.name, "value": a.value, "element": a} | a := attrs[_]}
    var_pairs := {{"name": v.name, "value": v.value, "element": v} | v := vars[_]}
    hash_pairs := {{"name": entry.key.value, "value": entry.value, "element": entry.value} |
        walk(node, [_, h])
        h.ir_type == "Hash"
        entry := h.value[_]
        entry.key.ir_type == "String"
    }
    pairs := attr_pairs | var_pairs | hash_pairs
}

value_has_any(val, patterns) {
    pattern := patterns[_]
    glitch_lib.traverse(val, pattern)
}

weak_key_size_number(name, n) {
    glitch_lib.contains(name, "curve")
    n < 224
}
weak_key_size_number(name, n) {
    glitch_lib.contains(name, "rsa")
    n <= 1536
}
weak_key_size_number(name, n) {
    glitch_lib.contains(name, "dh")
    n <= 1536
}
weak_key_size_number(name, n) {
    n == weak_sym_sizes[_]
}
weak_key_size_number(name, n) {
    n == weak_asym_sizes[_]
}

weak_key_size_string(name, s) {
    regex.match("^[0-9]+$", s)
    n := to_number(s)
    weak_key_size_number(name, n)
}
weak_key_size_string(name, s) {
    w := weak_keysize_tokens[_]
    regex.match(sprintf("(?i)(^|[^0-9])%s([^0-9]|$)", [w]), s)
}

weak_key_size_value(val, name) {
    walk(val, [_, v])
    v.ir_type == "Integer"
    weak_key_size_number(name, v.value)
}
weak_key_size_value(val, name) {
    walk(val, [_, v])
    v.ir_type == "Float"
    weak_key_size_number(name, v.value)
}
weak_key_size_value(val, name) {
    walk(val, [_, v])
    v.ir_type == "String"
    weak_key_size_string(name, v.value)
}

is_true(val) {
    val.ir_type == "Boolean"
    val.value == true
}
is_true(val) {
    val.ir_type == "String"
    regex.match("(?i)^(true|yes|1|on|enabled)$", val.value)
}
is_true(val) {
    val.ir_type == "Integer"
    val.value == 1
}

is_weak_kv(kv) {
    field_match(kv.name, algorithm_fields)
    glitch_lib.traverse(kv.value, weak_algo_pattern)
}
is_weak_kv(kv) {
    field_match(kv.name, algorithm_fields)
    glitch_lib.traverse(kv.value, weak_mode_pattern)
}
is_weak_kv(kv) {
    field_match(kv.name, protocol_fields)
    glitch_lib.traverse(kv.value, weak_protocol_pattern)
}
is_weak_kv(kv) {
    field_match(kv.name, cipher_fields)
    value_has_any(kv.value, weak_cipher_patterns)
}
is_weak_kv(kv) {
    field_match(kv.name, keysize_fields)
    weak_key_size_value(kv.value, kv.name)
}
is_weak_kv(kv) {
    field_match(kv.name, mode_fields)
    glitch_lib.traverse(kv.value, weak_mode_pattern)
}
is_weak_kv(kv) {
    field_match(kv.name, legacy_flag_fields)
    is_true(kv.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    kvs := all_kv_pairs(parent)
    kv := kvs[_]
    is_weak_kv(kv)

    result := {
        "type": "sec_weak_crypt",
        "element": kv.element,
        "path": parent.path,
        "description": weak_description
    }
}