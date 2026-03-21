package glitch

import data.glitch_lib

weak_algo_pattern := "(?i).*(3des|rc2|rc4|blowfish|\\bidea\\b|\\bcast\\b|\\bseed\\b|\\bxor\\b|rot13|\\bnull\\b|export|md5|sha1|\\bdes\\b).*"
weak_proto_pattern := "(?i).*(sslv2|sslv3|tls1\\.0|tls1\\.1|tlsv1\\.0|tlsv1\\.1|legacy|compatibility).*"
weak_cipher_pattern := "(?i).*(\\blow\\b|\\bmedium\\b|rc4|3des|\\bdes\\b|\\bnull\\b|anull|enull|export|md5|sha1).*"

algo_fields := {"encryption_algorithm", "encryption_type", "cipher", "algorithm", "encryption", "storage_encryption", "server_side_encryption", "kms_key_spec", "key_type"}
proto_fields := {"protocol", "min_protocol_version", "tls_version", "ssl_version", "ssl_policy", "security_policy", "allowed_protocols"}
cipher_fields := {"cipher_suites", "cipher_list", "cipher_suite", "ciphers", "ciphersuites", "ssl_policy", "security_policy"}
key_fields := {"key_size", "key_length", "key_bits", "keysize", "keylength", "bits", "rsa_key_bits", "dsa_key_bits", "dh_param_bits", "key_spec", "curve", "key_type"}

weak_key_values := {40, 56, 64, 80, 512, 768, 1024}

asym_terms := {"rsa", "dsa", "dh", "param", "modulus"}
ecc_terms := {"curve", "ecc", "ec"}

keyvalue(parent, kv) {
    attrs := glitch_lib.all_attributes(parent)
    kv = attrs[_]
}

keyvalue(parent, kv) {
    vars := glitch_lib.all_variables(parent)
    kv = vars[_]
}

field_match(name, fields) {
    f := fields[_]
    glitch_lib.contains(name, f)
}

asym_field(name) {
    t := asym_terms[_]
    glitch_lib.contains(name, t)
}

ecc_field(name) {
    t := ecc_terms[_]
    glitch_lib.contains(name, t)
}

value_match(value, pattern) {
    walk(value, [_, n])
    n.ir_type == "String"
    regex.match(pattern, n.value)
}

value_match(value, pattern) {
    walk(value, [_, n])
    n.ir_type == "VariableReference"
    regex.match(pattern, n.value)
}

value_match(value, pattern) {
    walk(value, [_, n])
    n.ir_type == "FunctionCall"
    regex.match(pattern, n.name)
}

value_match(value, pattern) {
    walk(value, [_, n])
    n.ir_type == "MethodCall"
    regex.match(pattern, n.method)
}

numeric_value(value, num) {
    walk(value, [_, n])
    n.ir_type == "Integer"
    num = n.value
}

numeric_value(value, num) {
    walk(value, [_, n])
    n.ir_type == "Float"
    num = n.value
}

numeric_value(value, num) {
    walk(value, [_, n])
    n.ir_type == "String"
    regex.match("^\\s*\\d+\\s*$", n.value)
    num = to_number(n.value)
}

numeric_value(value, num) {
    walk(value, [_, n])
    n.ir_type == "String"
    regex.match(".*\\d+.*", n.value)
    matches := regex.find_n("\\d+", n.value, 1)
    count(matches) > 0
    num = to_number(matches[0])
}

weak_key_length(name, val) {
    val == weak_key_values[_]
}

weak_key_length(name, val) {
    asym_field(name)
    val < 2048
}

weak_key_length(name, val) {
    ecc_field(name)
    val < 224
}

weak_key_length(name, val) {
    not asym_field(name)
    not ecc_field(name)
    val < 128
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    keyvalue(parent, kv)
    field_match(kv.name, algo_fields)
    value_match(kv.value, weak_algo_pattern)

    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or legacy encryption algorithm detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    keyvalue(parent, kv)
    field_match(kv.name, proto_fields)
    value_match(kv.value, weak_proto_pattern)

    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Inadequate encryption strength - Outdated cryptographic protocol version detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    keyvalue(parent, kv)
    field_match(kv.name, cipher_fields)
    value_match(kv.value, weak_cipher_pattern)

    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cipher suite or policy detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    keyvalue(parent, kv)
    field_match(kv.name, key_fields)
    numeric_value(kv.value, val)
    weak_key_length(kv.name, val)

    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Inadequate encryption strength - Insufficient key length or strength detected. (CWE-326)"
    }
}