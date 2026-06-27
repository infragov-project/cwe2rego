package glitch

import data.glitch_lib

weak_algorithms := {"des", "3des", "rc4", "rc2", "md5", "sha1", "sha-1", "desede", "blowfish", "ecb", "cbc", "aes-128", "aes-256-ecb"}

weak_key_bits := {512, 1024, 128}

encryption_attributes := {"encryption", "encryption_algorithm", "cipher", "cipher_suite", "algorithm", "crypto_algorithm", "kms_key_id", "ssl_policy", "tls_policy", "protocol", "ssl_protocol", "tls_version"}

key_size_attributes := {"key_size", "key_length", "key_length_bits", "bits", "key_bits", "rsa_bits", "dsa_bits", "ec_bits", "modulus_bits"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == encryption_attributes[_]
    glitch_lib.traverse(attr.value, weak_algorithms)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak encryption algorithm detected. Use strong encryption algorithms such as AES-256-GCM or ChaCha20-Poly1305. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == key_size_attributes[_]
    attr.value.ir_type == "Integer"
    attr.value.value <= 128

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak key size detected. Use key sizes of at least 256 bits for symmetric encryption and 2048 bits for asymmetric encryption. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == key_size_attributes[_]
    attr.value.ir_type == "String"
    bits := to_number(attr.value.value)
    bits <= 128

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak key size detected. Use key sizes of at least 256 bits for symmetric encryption and 2048 bits for asymmetric encryption. (CWE-326)"
    }
}