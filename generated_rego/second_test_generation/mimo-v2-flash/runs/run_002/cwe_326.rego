package glitch

import data.glitch_lib

weak_attr_names := {"algorithm", "cipher", "encryption_type", "protocol", "hashing_algorithm", "ssl_policy", "min_protocol", "signature_algorithm", "key_derivation", "mode", "operation_mode", "block_cipher_mode", "certificate_algorithm", "key_size", "key_length", "bits", "strength", "size", "hash_algo", "ssl_protocols", "ssl_cipher_suite", "ssl_protocol"}

weak_strings := {"des", "3des", "rc4", "blowfish", "aes-128", "aes128", "aes_128", "rsa-1024", "rsa1024", "rsa_1024", "dsa-1024", "dsa1024", "dsa_1024", "md5", "sha1", "sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1_0", "tls1.0", "tls1_0", "tlsv1.1", "tlsv1_1", "tls1.1", "tls1_1", "ecb", "cbc", "pbkdf1", "export", "null", "rc4-sha"}

is_weak_key_size(n) {
    n < 128
}
is_weak_key_size(n) {
    n == 512
}
is_weak_key_size(n) {
    n == 1024
}

is_weak_string(s) {
    lower_s := lower(s)
    # Iterate over the weak_strings set using index notation (Rego V0 compatible)
    weak_str := weak_strings[_]
    contains(lower_s, weak_str)
    not regex.match(sprintf("[-!]\\b%s\\b", [weak_str]), lower_s)
}

is_weak_value(v) {
    v.ir_type == "String"
    is_weak_string(v.value)
}
is_weak_value(v) {
    v.ir_type == "Array"
    item := v.value[_]
    item.ir_type == "String"
    is_weak_string(item.value)
}
is_weak_value(v) {
    v.ir_type == "String"
    num := to_number(v.value)
    num != null
    is_weak_key_size(num)
}
is_weak_value(v) {
    v.ir_type == "Integer"
    is_weak_key_size(v.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in weak_attr_names
    is_weak_value(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak encryption algorithm or key size detected. (CWE-326)"
    }
}