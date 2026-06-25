package glitch

import data.glitch_lib

weak_cipher_attr_pattern := "(?i)^(algorithm|cipher|encryption_algorithm|cipher_suite|encryption_type|crypto_algorithm|cipher_type|sse_algorithm|server_side_encryption|default_encryption|storage_encryption)$"

weak_cipher_value_pattern := "(?i)^(DES|3DES|TDEA|RC2|RC4|RC5|Blowfish|IDEA|TEA|ECB|AES.{0,5}ECB|AES.{0,5}128.{0,5}ECB)$"

weak_hash_attr_pattern := "(?i)^(hash_algorithm|digest_algorithm|checksum_type|integrity_algorithm|signature_algorithm|message_digest|hash_function|signing_algorithm|certificate_algorithm|signature_hash_algorithm|master_key_spec|password_encryption)$"

weak_hash_value_pattern := "(?i)^(MD2|MD4|MD5|SHA1|SHA-1|SHA_1|RIPEMD.{0,5}128|SHA1WithRSA|MD5WithRSA|sha1RSA|md5RSA|HMAC.{0,5}SHA1)$"

weak_tls_attr_pattern := "(?i)^(ssl_policy|tls_policy|minimum_protocol_version|ssl_protocols|tls_version|protocol_version|security_policy|enabled_protocols|accepted_protocols|supported_protocols)$"

weak_tls_value_pattern := "(?i)^(SSLv2|SSLv3|TLSv1|TLSv1.0|TLSv1.1|TLS1|TLS1_0|TLS1_1|TLS_1_0|TLS_1_1|SSL_2_0|SSL_3_0)$"

weak_key_size_attr_pattern := "(?i)^(key_size|key_length|rsa_bits)$"

weak_vpn_attr_pattern := "(?i)^(phase1_encryption_algorithm|phase2_encryption_algorithm|integrity_algorithm|prf_algorithm|dh_group|vpn_encryption|tunnel_encryption|ipsec_policy)$"

weak_vpn_value_pattern := "(?i)^(3des|des|md5|sha1|group1|group2|group5)$"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match(weak_cipher_attr_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(weak_cipher_value_pattern, attr.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak symmetric encryption algorithm detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match(weak_hash_attr_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(weak_hash_value_pattern, attr.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak hashing algorithm detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match(weak_tls_attr_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(weak_tls_value_pattern, attr.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Insecure TLS/SSL protocol version detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match(weak_tls_attr_pattern, attr.name)
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    regex.match(weak_tls_value_pattern, elem.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Insecure TLS/SSL protocol version in list detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match("(?i)^(cipher_suites|allowed_ciphers|enabled_ciphers|ssl_ciphers|cipher_list|tls_cipher_policy|preferred_ciphers)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i).*(NULL|EXPORT|ANON|RC4|_DES_|3DES|WITH_MD5).*", attr.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak cipher suite detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match(weak_key_size_attr_pattern, attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value < 2048

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Insufficient key size (less than 2048 bits) detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match("(?i)^(key_algorithm|key_type|key_spec|asymmetric_algorithm)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(DSA|DH)$", attr.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak asymmetric key algorithm detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match(weak_vpn_attr_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(weak_vpn_value_pattern, attr.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak VPN/tunnel cryptographic algorithm detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match("(?i)^(fips_enabled|enforce_ssl|verify_ssl)$", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Strong cryptography has been explicitly disabled. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match("(?i)^(insecure_ssl|disable_tls|allow_legacy_renegotiation)$", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Insecure SSL/TLS option has been explicitly enabled. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match("(?i)^(ssl_mode|tls_mode)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(none|disabled|allow|off)$", attr.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - SSL/TLS has been disabled or set to an insecure mode. (CWE-327)"
    }
}