package glitch

import data.glitch_lib

weak_algo_attr_names := {"algorithm", "encryption_algorithm", "cipher", "cipher_suite", "hash_algorithm", "digest_algorithm", "signing_algorithm", "key_algorithm", "encryption_type", "server_side_encryption", "block_cipher_mode", "certificate_algorithm", "signature_algorithm", "phase1_encryption", "phase2_encryption"}

weak_tls_attr_names := {"ssl_policy", "tls_policy", "minimum_tls_version", "min_tls_version", "security_policy", "ssl_protocol"}

key_size_attr_names := {"key_size", "key_length", "key_bits", "rsa_bits", "modulus_length", "bit_length"}

https_attr_names := {"https_only", "enforce_https"}

rotation_attr_names := {"rotation_enabled", "enable_key_rotation"}

dh_group_attr_names := {"dh_group", "diffie_hellman_group"}

weak_key_sizes := {512, 768, 1024}

weak_dh_groups := {1, 2, 5}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_algo_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(\\bDES\\b|\\b3DES\\b|\\bRC2\\b|\\bRC4\\b|\\bBlowfish\\b|\\bECB\\b|\\bMD5\\b|\\bMD4\\b|\\bMD2\\b|\\bSHA-?1\\b|\\bNULL\\b|\\bEXPORT\\b|\\banon\\b)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak or deprecated encryption/hash algorithm detected - Use strong algorithms such as AES-256-GCM or SHA-256. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_tls_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(SSLv2|SSLv3|TLSv?1[._]?0|TLSv?1[._]?1|TLS1_0|TLS1_1)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak or deprecated TLS/SSL protocol version detected - Use TLS 1.2 or higher. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == key_size_attr_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value == weak_key_sizes[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient cryptographic key size detected - Use at least 2048 bits for RSA/DSA keys. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == key_size_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("^(512|768|1024)$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient cryptographic key size detected - Use at least 2048 bits for RSA/DSA keys. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == https_attr_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "HTTPS enforcement is disabled - Enable HTTPS to ensure encrypted communication. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == rotation_attr_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Cryptographic key rotation is disabled - Enable key rotation to maintain encryption strength over time. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == dh_group_attr_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value == weak_dh_groups[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak Diffie-Hellman group detected - Use DH group 14 or higher for sufficient key exchange strength. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == dh_group_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(\\bgroup[125]\\b|modp768|modp1024|\\bgroup1\\b|\\bgroup2\\b|\\bgroup5\\b)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak Diffie-Hellman group detected - Use DH group 14 or higher for sufficient key exchange strength. (CWE-326)"
    }
}