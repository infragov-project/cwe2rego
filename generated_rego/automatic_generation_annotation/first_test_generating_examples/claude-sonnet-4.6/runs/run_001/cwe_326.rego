package glitch

import data.glitch_lib

weak_key_sizes := {40, 56, 64, 112, 512, 768, 1024}

weak_algo_pattern := "(?i)^(DES|3DES|TDES|TDEA|RC2|RC4|ARC4|Blowfish|IDEA|MD5|SHA1|SHA-1|RSA_PKCS1_SHA1|ECDSA_SHA1|MD5withRSA|SHA1withRSA)$"

weak_tls_pattern := "(?i)(SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1|TLS_1_0|TLS_1_1|TLS-1-0|TLS-1-1|2016-08|ELBSecurityPolicy-2015)"

weak_cipher_pattern := "(?i)(\\bRC4\\b|\\bDES\\b|\\bNULL\\b|EXPORT|\\bANON\\b)"

weak_vpn_algo_pattern := "(?i)(3des|tdes|tdea|\\bdes\\b|\\brc4\\b|arc4|\\brc2\\b|\\bmd5\\b|\\bsha1\\b|sha-1)"

key_size_attr_names := {"key_size", "key_length", "key_bits", "rsa_bits", "modulus_length", "bit_length", "size"}

algo_attr_names := {"algorithm", "encryption_algorithm", "cipher_algorithm", "cipher", "kms_key_spec", "sse_algorithm", "signature_algorithm", "key_algorithm", "signing_algorithm", "key_spec", "digest"}

tls_attr_names := {"ssl_policy", "tls_policy", "security_policy", "minimum_protocol_version", "min_tls_version", "ssl_protocol", "tls_version", "protocol_version", "minimum_tls_version"}

cipher_attr_names := {"cipher_suite", "ciphers", "cipher_list", "enabled_ssl_protocols", "ssl_ciphers"}

vpn_proposal_attr_names := {"ike_proposals", "esp_proposals", "phase1_encryption_algorithms", "phase2_encryption_algorithms", "encryption_algorithms", "integrity_algorithms"}

enc_at_rest_attr_names := {"storage_encrypted", "encrypt_at_rest"}

dh_scalar_attr_names := {"dh_group", "dh_groups"}

weak_dh_groups := {1, 2, 5}

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
        "description": "Inadequate Encryption Strength - Weak key size. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(dhparam_size|dh_param_size|dh_bits)", attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value == weak_key_sizes[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak DH parameter size. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == algo_attr_names[_]
    attr.value.ir_type == "String"
    regex.match(weak_algo_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == tls_attr_names[_]
    attr.value.ir_type == "String"
    regex.match(weak_tls_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Outdated TLS/SSL protocol. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cipher_attr_names[_]
    attr.value.ir_type == "String"
    regex.match(weak_cipher_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher suite. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "line"
    attr.value.ir_type == "String"
    regex.match("(?i)ssl_protocols?\\s", attr.value.value)
    regex.match(weak_tls_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Outdated TLS/SSL protocol in config line. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "line"
    attr.value.ir_type == "String"
    regex.match("(?i)(ssl_ciphers|SSLCipherSuite)\\s", attr.value.value)
    regex.match(weak_cipher_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher in config line. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "content"
    attr.value.ir_type == "String"
    regex.match("(?i)(SSLCipherSuite|ssl_ciphers)", attr.value.value)
    regex.match(weak_cipher_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher in content block. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == enc_at_rest_attr_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Encryption at rest disabled. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "ike_version"
    attr.value.ir_type == "String"
    regex.match("(?i)^ikev?1$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak IKE version. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == dh_scalar_attr_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value == weak_dh_groups[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak DH group. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == vpn_proposal_attr_names[_]
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    regex.match(weak_vpn_algo_pattern, elem.value)
    first_elem := attr.value.value[0]
    result := {
        "type": "sec_weak_crypt",
        "element": first_elem,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak algorithm in VPN proposal. (CWE-326)"
    }
}