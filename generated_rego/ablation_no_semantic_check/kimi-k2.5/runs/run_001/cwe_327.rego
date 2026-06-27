package glitch

import data.glitch_lib

# Weak cryptographic algorithms and protocols
weak_algorithms := {
    "DES", "3DES", "MD5", "SHA1", "SHA-1", "RC4", "RC2", "BLOWFISH", "TEA", "XTEA",
    "ECB", "CBC", "SSL", "SSLv2", "SSLv3", "TLS1.0", "TLS1.1", "TLS_1_0", "TLS_1_1",
    "RSA_1024", "RSA_512", "PKCS1v15", "SSH1", "SSH-RSA", "ssh-dss", "ssh-rsa",
    "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1",
    "NULL", "none", "no_padding", "AH"
}

weak_algorithm_patterns := {
    "(?i)DES[^a-zA-Z]",
    "(?i)3DES",
    "(?i)MD5[^a-zA-Z]",
    "(?i)SHA[-_]?1[^0-9]",
    "(?i)RC4",
    "(?i)RC2",
    "(?i)BLOWFISH",
    "(?i)TEA[^a-zA-Z]",
    "(?i)XTEA",
    "(?i)ECB[^a-zA-Z]",
    "(?i)SSL[^a-zA-Z]*[23]",
    "(?i)TLS[-_]?1[-_]?[01][^0-9]",
    "(?i)TLS_1_0",
    "(?i)TLS_1_1",
    "(?i)1024[-_]?bit",
    "(?i)512[-_]?bit",
    "(?i)RSA[-_]?1024",
    "(?i)RSA[-_]?512",
    "(?i)PKCS1v15",
    "(?i)SSH[-_]?1",
    "(?i)SSH[-_]?RSA",
    "(?i)ssh[-_]?dss",
    "(?i)ssh[-_]?rsa",
    "(?i)diffie[-_]?hellman[-_]?group[-_]?1[-_]?sha1",
    "(?i)diffie[-_]?hellman[-_]?group[-_]?exchange[-_]?sha1",
    "(?i)NULL[^a-zA-Z]",
    "(?i)^none$",
    "(?i)no[-_]?padding",
    "(?i)^AH$"
}

# Cryptographic attribute names
crypto_attributes := {
    "algorithm", "encryption_algorithm", "hash_algorithm", "signature_algorithm",
    "cipher", "crypto", "kex_algorithms", "mac_algorithms", "tls_version",
    "ssl_policy", "protocol_version", "min_tls_version", "security_policy",
    "key_size", "key_length", "rsa_key_bits", "minimum_rsa_key_size",
    "block_cipher_mode", "encryption_mode", "padding", "policy",
    "security_profile", "cipher_suites", "protocols", "ike_version",
    "ipsec_policy", "phase1_policy", "phase2_policy", "storage_encrypted",
    "kms_key_id", "encryption", "key_spec", "key_usage", "customer_master_key_spec",
    "host_key_algorithm", "ciphers", "macs", "kex", "sse_algorithm",
    "bucket_key_enabled", "key_algorithm", "allowed_algorithms", "permitted_ciphers",
    "supported_protocols"
}

# Check if a string value contains weak algorithm
contains_weak_algorithm(value) {
    weak_algorithm_patterns[pattern]
    regex.match(pattern, value)
}

# Check string value for weak algorithms
check_weak_crypto_string(value) {
    value.ir_type == "String"
    contains_weak_algorithm(value.value)
}

# Check integer value for weak key sizes
check_weak_key_size(value) {
    value.ir_type == "Integer"
    value.value < 2048
}

# Traverse value to find weak crypto references
has_weak_crypto(value) {
    walk(value, [_, node])
    node.ir_type == "String"
    contains_weak_algorithm(node.value)
}

# Check if attribute name is crypto-related
is_crypto_attribute(name) {
    crypto_attributes[name]
}

# Check for weak encryption disabled explicitly
is_weak_encryption_disabled(attr) {
    attr.name == "storage_encrypted"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
}

# Check for weak encryption disabled with string
is_weak_encryption_disabled(attr) {
    attr.name == "storage_encrypted"
    attr.value.ir_type == "String"
    lower(attr.value.value) == "false"
}

# Check for weak encryption disabled with encrypted attribute
is_weak_encryption_disabled(attr) {
    attr.name == "encrypted"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
}

# Check for weak encryption disabled with string
is_weak_encryption_disabled(attr) {
    attr.name == "encrypted"
    attr.value.ir_type == "String"
    lower(attr.value.value) == "false"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    units := glitch_lib.all_atomic_units(parent)
    node := units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_crypto_attribute(attr.name)
    check_weak_crypto_string(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm - Avoid using broken or risky cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    units := glitch_lib.all_atomic_units(parent)
    node := units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_crypto_attribute(attr.name)
    has_weak_crypto(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm - Avoid using broken or risky cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    units := glitch_lib.all_atomic_units(parent)
    node := units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_crypto_attribute(attr.name)
    check_weak_key_size(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cryptographic key size - Avoid using small cryptographic key sizes. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    units := glitch_lib.all_atomic_units(parent)
    node := units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_weak_encryption_disabled(attr)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption explicitly disabled - Avoid disabling encryption for storage or transmission. (CWE-327)"
    }
}