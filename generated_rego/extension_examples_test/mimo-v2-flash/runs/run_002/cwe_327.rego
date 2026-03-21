package glitch

import data.glitch_lib

crypto_attrs := {"encryption_algorithm", "algorithm", "cipher", "encryption_type", "hashing_algorithm", "digest_algorithm", "password_hash", "signature_algorithm", "protocol", "ssl_policy", "tls_version", "min_protocol_version", "cipher_suites", "ssl_ciphers", "mode", "block_cipher_mode", "key_size", "key_length"}

weak_algorithms := {"DES", "3DES", "RC4", "AES-128", "BLOWFISH", "TWOFISH", "MD5", "SHA-1", "SHA1", "HMAC-MD5", "HMAC-SHA1", "md5_crypt"}

weak_protocols := {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLS_1_0", "TLS_1_1"}

weak_ciphers := {"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "SHA1"}

weak_modes := {"ECB"}

weak_key_sizes := {1024, 160}

contains_weak_pattern(str) {
    regex.match("(?i).*(DES|3DES|RC4|AES-128|BLOWFISH|TWOFISH|MD5|SHA-?1|HMAC-MD5|HMAC-SHA1|md5_crypt)", str)
}

contains_weak_pattern(str) {
    regex.match("(?i).*(SSLv2|SSLv3|TLSv1|TLSv1\\.1|TLS_1_0|TLS_1_1)", str)
}

contains_weak_pattern(str) {
    regex.match("(?i).*(RC4|DES|3DES|NULL|EXPORT|MD5|SHA1)", str)
}

contains_weak_pattern(str) {
    regex.match("(?i).*ECB", str)
}

check_weak_value(node) {
    node.ir_type == "String"
    contains_weak_pattern(node.value)
}

check_weak_value(node) {
    node.ir_type == "VariableReference"
    contains_weak_pattern(node.value)
}

check_weak_value(node) {
    node.ir_type == "Integer"
    node.value == 1024
}

check_weak_value(node) {
    node.ir_type == "Integer"
    node.value == 160
}

check_weak_value_in_complex(node) {
    walk(node, [_, leaf])
    check_weak_value(leaf)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in crypto_attrs
    check_weak_value_in_complex(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    check_weak_value_in_complex(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    check_weak_value_in_complex(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm (CWE-327)"
    }
}