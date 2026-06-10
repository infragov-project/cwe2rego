package glitch

import data.glitch_lib

weak_algorithms := {"DES", "RC4", "3DES", "MD2", "MD4", "MD5", "SHA1", "ECB", "Blowfish", "XOR", "ROT-25", "TEA", "AES-128"}
weak_protocols := {"ssl-v2", "ssl-v3", "tls-1.0", "tls-1.1", "legacy", "insecure", "SSLv3", "TLS1_0", "TLS1_1"}
weak_key_sizes := {1024, 56}
weak_block_modes := {"ECB"}
weak_cipher_suites := {"RC4", "DES-CBC3-SHA", "NULL", "EXPORT"}

weak_crypto_attributes := {"algorithm", "encryption", "hashing_algorithm", "signature_algorithm", "protocol_version", "cipher_suites", "tls_policy", "min_tls_version", "key_size", "key_length", "block_mode", "nonce_size"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name in weak_crypto_attributes

    attr.value.ir_type == "String"
    value := attr.value.value
    value in weak_algorithms or value in weak_protocols or value in weak_block_modes

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name in weak_crypto_attributes

    attr.value.ir_type == "Integer"
    value := attr.value.value
    value in weak_key_sizes

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of insufficient key size (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "cipher_suites"
    attr.value.ir_type == "Array"
    array_value := attr.value.value
    some i
    array_value[i].ir_type == "String"
    array_value[i].value in weak_cipher_suites

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cipher suite (CWE-327)"
    }
}