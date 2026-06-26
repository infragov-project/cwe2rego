package glitch

import data.glitch_lib

asymmetric_key_fields := {"rsa_bits", "key_length", "key_size", "modulus_length", "bit_length"}

tls_version_fields := {"minimum_tls_version", "tls_version", "protocol", "min_protocol_version", "ssl_policy", "security_policy"}

algorithm_fields := {"algorithm", "encryption_algorithm", "cipher", "cipher_suite", "ciphers", "ssl_ciphers", "cipher_algorithms", "kms_key_spec", "key_spec", "signing_algorithm", "certificate_algorithm"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == asymmetric_key_fields[_]
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Asymmetric key size is below the recommended minimum of 2048 bits. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "key_bits"
    attr.value.ir_type == "Integer"
    attr.value.value < 128
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Symmetric key size is below the recommended minimum of 128 bits. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == algorithm_fields[_]
    attr.value.ir_type == "String"
    regex.match(`(?i).*(^|[^A-Za-z])(DES|3DES|TripleDES|RC2|RC4|RC5|Blowfish|MD5|SHA-?1|NULL|EXPORT|ANON|AES[-_]128|RSA[-_]1024|SHA1with|MD5with)([^A-Za-z]|$).*`, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak or deprecated cryptographic algorithm configured. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == tls_version_fields[_]
    attr.value.ir_type == "String"
    regex.match(`(?i).*(TLSv?1\.[01]|SSLv?[23]|TLS-1-[01]|ELBSecurityPolicy-2015).*`, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak or deprecated TLS/SSL protocol version configured. (CWE-326)"
    }
}