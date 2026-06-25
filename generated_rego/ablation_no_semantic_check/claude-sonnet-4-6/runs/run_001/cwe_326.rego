package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(algorithm|encryption_algorithm|cipher|cipher_suite|server_side_encryption|encryption_type|sse_algorithm)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(DES|3DES|TRIPLE.?DES|RC4|RC2|IDEA|BLOWFISH|ECB)$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak or broken encryption algorithm detected. Avoid DES, 3DES, RC4, RC2, IDEA, Blowfish, and ECB mode. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(tls_version|ssl_version|min_tls_version|minimum_tls_version|ssl_policy|security_policy|protocol_policy)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(SSLv2|SSLv3|TLSv1|TLSv1[._]0|TLSv1[._]1|TLS[_]1[_]0|TLS[_]1[_]1|.*TLS.*1[._]0.*|.*TLS.*1[._]1.*)$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak or deprecated TLS/SSL version detected. Use TLS 1.2 or higher. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(hash_algorithm|digest_algorithm|signing_algorithm|hashing_method)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(MD5|SHA1|SHA-1|MD4|MD2)$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak or broken hash algorithm detected. Avoid MD5, SHA1, MD4, and MD2 for cryptographic purposes. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(key_size|key_length|key_bits|rsa_bits|modulus_size|bit_strength|dsa_key_size)$", attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient cryptographic key size. RSA/DSA keys must be at least 2048 bits. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(cipher_suite|allowed_ciphers|ssl_ciphers|predefined_policy)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i).*(NULL|EXPORT|RC4|[_-]DES[_-]|WITH_DES|_3DES_|WITH_3DES|ANON|[_-]MD5).*", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cipher suite detected. Avoid NULL, EXPORT, RC4, DES, 3DES, anonymous, and MD5-based ciphers. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(key_algorithm|signature_algorithm|key_type|ec_curve)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(RSA.?1024|DSA.?1024|P.?192)$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak asymmetric or signing key configuration detected. Avoid RSA-1024, DSA-1024, and P-192 elliptic curve. (CWE-326)"
    }
}