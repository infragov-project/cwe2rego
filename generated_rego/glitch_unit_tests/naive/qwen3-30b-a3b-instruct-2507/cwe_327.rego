package glitch

import data.glitch_lib

weak_algorithms := [
    "DES", "DES3", "3DES", "MD5", "SHA1", "RC4", "RC5", "RC6", "TEA", "XTEA", "XXTEA",
    "HMAC-MD5", "HMAC-SHA1", "ECB", "CBC", "SHA-256", "SHA-384", "SHA-512", "SHA3-256",
    "SHA-224", "SHA3-224", "SHA3-384", "SHA3-512", "DH-512", "SSLv3", "TLS_RSA_WITH_DES_CBC_SHA",
    "PKCS1v15", "ROT-25", "ROT25", "XOR", "character swap", "swapped characters", "obfuscation"
]

key_derivation_weaknesses := [
    "PBKDF1", "simple_concat", "no salt", "no work factor", "no iteration", "no rounds"
]

mode_weaknesses := [
    "ECB", "CBC", "CBC with fixed IV", "IV reuse", "IV not random", "IV not unique"
]

cryptography_fields := [
    "algorithm", "hash", "cipher", "mode", "encryption_method", "key_size",
    "key_derivation", "security_protocol", "hash_function", "message_authentication",
    "cryptographic_accelerator", "encryption_module", "signature_scheme", "obfuscation",
    "default_config", "fallback_strategy", "cipher_suite", "key_exchange", "padding"
]

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "algorithm" or
    attr.name == "hash" or
    attr.name == "cipher" or
    attr.name == "mode" or
    attr.name == "encryption_method" or
    attr.name == "key_size" or
    attr.name == "key_derivation" or
    attr.name == "security_protocol" or
    attr.name == "hash_function" or
    attr.name == "message_authentication" or
    attr.name == "cryptographic_accelerator" or
    attr.name == "encryption_module" or
    attr.name == "signature_scheme" or
    attr.name == "obfuscation" or
    attr.name == "default_config" or
    attr.name == "fallback_strategy" or
    attr.name == "cipher_suite" or
    attr.name == "key_exchange" or
    attr.name == "padding"

    attr.value.ir_type == "String"
    string_value := attr.value.value
    lower_value := to_lower(string_value)

    weak_alg := weak_algorithms[_]
    regex.match(sprintf("(?i).*%s.*", [weak_alg]), lower_value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Use of a broken or risky cryptographic algorithm: %s found in field '%s' (%s). This may indicate CWE-327.", [string_value, attr.name, attr.value.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "key_size"
    attr.value.ir_type == "Integer"
    attr.value.value < 128

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Key size is insufficient (less than 128 bits). This may indicate the use of weak cryptographic key strength (CWE-327)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "key_derivation"
    attr.value.ir_type == "String"
    string_value := attr.value.value
    low_value := to_lower(string_value)

    weakness := key_derivation_weaknesses[_]
    regex.match(sprintf("(?i).*%s.*", [weakness]), low_value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Use of weak key derivation: %s. This may indicate insecure key stretching (CWE-327).", [string_value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "security_protocol"
    attr.value.ir_type == "String"
    string_value := attr.value.value
    lower_value := to_lower(string_value)

    regex.match("(?i)SSLv3|TLSv1\\.0|TLSv1\\.1", lower_value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Use of deprecated security protocol: %s. This may indicate weak or outdated cryptography (CWE-327).", [string_value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "hash_function"
    attr.value.ir_type == "String"
    string_value := attr.value.value
    lower_value := to_lower(string_value)

    regex.match("(?i)MD5|SHA1|SHA224|SHA-224", lower_value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Use of weak hash function: %s. Collision attacks are possible (CWE-327).", [string_value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "signature_scheme"
    attr.value.ir_type == "String"
    string_value := attr.value.value
    lower_value := to_lower(string_value)

    regex.match("(?i)RSA-SHA1|RSA-MD5|ECDSA-SHA1", lower_value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Use of weak signature scheme: %s. Digital signatures may be forged (CWE-327).", [string_value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "encryption_module"
    attr.value.ir_type == "String"
    string_value := attr.value.value
    lower_value := to_lower(string_value)

    regex.match("(?i)DES_IP|SHA1_IP|MD5_IP|TEA_IP", lower_value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Use of deprecated cryptographic IP: %s. This may indicate weak hardware-level cryptography (CWE-327).", [string_value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "cryptographic_accelerator"
    attr.value.ir_type == "String"
    string_value := attr.value.value
    lower_value := to_lower(string_value)

    regex.match("(?i)SHA1_IP|DES_IP|MD5_IP", lower_value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Use of deprecated cryptographic accelerator: %s. This may indicate weak hardware-level cryptography (CWE-327).", [string_value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "default_config" or attr.name == "fallback_strategy"
    attr.value.ir_type == "String"
    string_value := attr.value.value
    lower_value := to_lower(string_value)

    regex.match("(?i)MD5|SHA1|DES|3DES|HMAC-SHA1|HMAC-MD5|crypto_weak", lower_value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Use of weak fallback or default cryptographic setting: %s (CWE-327).", [string_value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "cipher_suite"
    attr.value.ir_type == "String"
    string_value := attr.value.value
    lower_value := to_lower(string_value)

    regex.match("(?i)DES|CVE-2016-2183|SSLv3|RC4|NULL", lower_value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Use of weak cipher suite: %s. This may indicate inadequate encryption (CWE-327).", [string_value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "key_exchange"
    attr.value.ir_type == "String"
    string_value := attr.value.value
    lower_value := to_lower(string_value)

    regex.match("(?i)DH-512|DH-1024", lower_value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Use of weak key exchange: %s. Diffie-Hellman modulus too small (CWE-327).", [string_value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "padding"
    attr.value.ir_type == "String"
    lower_value := to_lower(attr.value.value)

    lower_value == "pkcs1v15"

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of PKCS#1 v1.5 padding in RSA operations. Vulnerable to padding oracle attacks (CWE-327)."
    }
}