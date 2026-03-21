package glitch

import data.glitch_lib

cipher_attr_names := {"algorithm", "encryption_algorithm", "cipher", "cipher_type", "sse_algorithm"}
asym_key_attr_names := {"key_size", "key_length", "rsa_bits", "key_bits", "modulus_bits", "bit_length", "key_spec"}
sym_key_attr_names := {"key_size", "key_length", "key_bits", "key_spec"}
tls_attr_names := {"ssl_policy", "security_policy", "minimum_protocol_version", "min_tls_version", "tls_version", "protocol_version", "ssl_protocol", "minimum_ssl_protocol", "tls_policy"}
hash_attr_names := {"hash_algorithm", "hashing_algorithm", "digest_algorithm", "signature_algorithm", "checksum_algorithm", "integrity_algorithm"}
curve_attr_names := {"ecdsa_curve", "elliptic_curve", "curve_name", "ec_curve", "ec_key_type"}
cipher_suite_attr_names := {"cipher_suites", "enabled_ciphers", "allowed_ciphers", "ssl_ciphers", "preferred_ciphers"}
dh_attr_names := {"dh_params", "dh_param_size", "diffie_hellman_group", "dh_group"}
cert_attr_names := {"key_algorithm", "signing_algorithm", "certificate_type"}
block_mode_attr_names := {"encryption_mode", "cipher_mode", "block_mode"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == cipher_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(\\bDES\\b|3DES|TRIPLE.DES|\\bRC4\\b|\\bRC2\\b|ARCFOUR|ECB)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak symmetric encryption algorithm used. Avoid DES, 3DES, RC4, RC2, ARCFOUR, and ECB. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == asym_key_attr_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value > 0
    attr.value.value <= 1024
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient asymmetric key length. Use at least 2048 bits for RSA/DSA keys. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == sym_key_attr_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value > 0
    attr.value.value < 128
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient symmetric key length. Use at least 128 bits for symmetric keys. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == tls_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(SSLv2|SSLv3|TLSv1|TLSv1\\.0|TLSv1\\.1|TLS_1_0|TLS_1_1)$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Deprecated TLS/SSL protocol version in use. Use TLS 1.2 or higher. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == hash_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(MD2|MD4|MD5|SHA1|SHA-1)$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak hash algorithm used. Avoid MD2, MD4, MD5, SHA1. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == curve_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(secp112|secp128|secp160)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak elliptic curve selected. Use curves with at least 224-bit security. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == cipher_suite_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(RC4|\\bDES\\b|NULL|EXPORT|ANON|\\bMD5\\b|ADH|AECDH)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cipher suite enabled. Avoid RC4, DES, NULL, EXPORT, ANON, MD5, ADH, AECDH. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == cipher_suite_attr_names[_]
    attr.value.ir_type == "Array"
    element := attr.value.value[_]
    element.ir_type == "String"
    regex.match("(?i)(RC4|\\bDES\\b|NULL|EXPORT|ANON|\\bMD5\\b|ADH|AECDH)", element.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cipher suite in list. Avoid RC4, DES, NULL, EXPORT, ANON, MD5, ADH, AECDH. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == dh_attr_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value > 0
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient Diffie-Hellman parameter size. Use at least 2048 bits. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == dh_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(modp768|modp1024|group.?[125]$)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak Diffie-Hellman group used. Use modp2048 or stronger. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == cert_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(RSA_512|RSA_1024|SHA1withRSA|MD5withRSA|SHA1withECDSA)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak certificate signature algorithm. Avoid RSA_1024, SHA1withRSA, MD5withRSA, SHA1withECDSA. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == block_mode_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(ECB|CBC|CFB)$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure block cipher mode. ECB is always insecure; CBC and CFB require separate integrity protection. (CWE-326)"
    }
}