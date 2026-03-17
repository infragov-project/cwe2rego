package glitch

import data.glitch_lib

weak_key_length_attrs := {"key_size", "key_length", "rsa_bits", "size"}
risky_key_sizes := {512, 1024}

weak_key_spec_attrs := {"key_spec", "key_algorithm", "private_key_type", "certificate_algorithm"}
weak_key_spec_values := {"RSA_1024", "RSA_512", "EC_prime192v1", "EC_SECT163", "ECDSA_P192"}

weak_sym_enc_attrs := {"algorithm", "encryption_algorithm", "cipher_algorithm", "cipher", "kms_algorithm"}
weak_sym_enc_values := {"DES", "3DES", "TRIPLE_DES", "RC2", "RC4", "ARCFOUR", "BLOWFISH"}

weak_tls_attrs := {"minimum_protocol_version", "minimum_tls_version", "ssl_policy", "security_policy", "tls_policy", "protocol_version", "ssl_support_method", "ssl_protocols"}
weak_tls_values := {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLS1_0", "TLS1_1", "TLS-1-0"}

weak_cipher_attrs := {"cipher_suites", "predefined_cipher_suite", "ciphers", "ssl_ciphers", "cipher_list", "enabled_ssl_protocols", "ssl_cipher_suite"}

weak_hash_attrs := {"hash_algorithm", "digest_algorithm", "signing_algorithm", "mac_algorithm", "integrity_algorithm", "digest"}
weak_hash_values := {"MD5", "SHA1", "SHA-1", "HMAC-MD5", "HMAC-SHA1", "RSA_WITH_MD5"}

weak_dh_attrs := {"dh_group", "phase1_dh_group_numbers", "phase2_dh_group_numbers", "ike_dh_group", "key_exchange"}
weak_dh_values := {"Group1", "Group2", "DHGroup1", "DHGroup2", "MODP768", "MODP1024"}

weak_vpn_attrs := {"phase1_encryption_algorithms", "phase2_encryption_algorithms", "ike_encryption_algorithm", "esp_encryption_algorithm"}
weak_vpn_values := {"DES", "3DES", "AES128"}

cipher_string_is_weak(s) {
    regex.match("(?i)(^|[: ,])(DES|3DES|RC4|NULL|EXPORT|ANON)", s)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_key_length_attrs[_]
    attr.value.ir_type == "Integer"
    attr.value.value == risky_key_sizes[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Cryptographic key length is too small. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_key_spec_attrs[_]
    glitch_lib.traverse(attr.value, weak_key_spec_values)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak asymmetric key algorithm or size specified. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_sym_enc_attrs[_]
    glitch_lib.traverse(attr.value, weak_sym_enc_values)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or deprecated symmetric encryption algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_tls_attrs[_]
    glitch_lib.traverse(attr.value, weak_tls_values)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or deprecated TLS/SSL protocol version. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_cipher_attrs[_]
    attr.value.ir_type == "String"
    cipher_string_is_weak(attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or insecure cipher suite configured. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_cipher_attrs[_]
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    cipher_string_is_weak(elem.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or insecure cipher suite configured. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_hash_attrs[_]
    glitch_lib.traverse(attr.value, weak_hash_values)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak hashing algorithm in cryptographic context. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_dh_attrs[_]
    glitch_lib.traverse(attr.value, weak_dh_values)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak Diffie-Hellman group configured. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_vpn_attrs[_]
    glitch_lib.traverse(attr.value, weak_vpn_values)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak VPN/IPSec phase encryption algorithm. (CWE-326)"
    }
}