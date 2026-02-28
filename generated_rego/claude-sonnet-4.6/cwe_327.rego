package glitch

import data.glitch_lib

tls_attr_names := {"ssl_policy", "tls_version", "minimum_tls_version", "ssl_protocol", "protocol_version", "max_protocol_version", "tls_min_version", "tls_max_version", "security_policy"}

cipher_attr_names := {"cipher_suite", "cipher", "ssl_cipher", "allowed_ciphers", "cipher_list", "encryption_algorithm", "cipher_policy"}

rsa_dh_key_attr_names := {"key_size", "key_length", "rsa_bits", "key_bits", "dh_key_length", "modulus_length", "bit_length"}

ec_key_attr_names := {"ec_key_size"}

hash_attr_names := {"hash_algorithm", "digest_algorithm", "checksum_algorithm", "signature_algorithm", "integrity_algorithm", "hmac_algorithm", "password_hash", "hashing_scheme"}

enc_at_rest_attr_names := {"server_side_encryption", "encryption_algorithm", "encryption_type", "sse_algorithm", "storage_encryption", "volume_encryption", "disk_encryption"}

vpn_attr_names := {"ike_version", "phase1_encryption", "phase2_encryption", "esp_algorithm", "pfs_group", "dh_group"}

cert_attr_names := {"cert_algorithm", "signing_algorithm", "certificate_policy"}

policy_attr_names := {"predefined_policy", "negotiation_policy", "listener_policy", "ssl_policy", "security_policy"}

auth_attr_names := {"auth_method", "auth_type", "authentication_method", "password_method", "auth", "authentication"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == tls_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i).*(SSLv?2|SSLv?3|TLSv?1\\.0|TLSv?1\\.1|TLS_1_0|TLS_1_1|TLS-1-0|TLS-1-1|TLS1_0|TLS1_1|FS-1-0|legacy|201[56]).*", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure TLS/SSL protocol version configured - Use TLSv1.2 or higher to protect data in transit. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cipher_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i).*(3DES|\\bDES\\b|\\bRC4\\b|\\bRC2\\b|\\bNULL\\b|EXPORT|\\bADH\\b|AECDH|\\bANON\\b|-MD5).*", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak or broken cipher suite specified - Avoid DES, 3DES, RC4, RC2, NULL, and EXPORT-grade ciphers. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == rsa_dh_key_attr_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient cryptographic key length - RSA/DH keys must be at least 2048 bits. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == ec_key_attr_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value < 224
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient EC key length - EC keys must be at least 224 bits. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == hash_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i).*(\\bMD4\\b|\\bMD5\\b|\\bSHA-?1\\b|hmac-md5|hmac-sha1|sha1WithRSAEncryption|md5WithRSAEncryption).*", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Deprecated or broken hashing algorithm - Avoid MD4, MD5, and SHA-1 for cryptographic operations. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == enc_at_rest_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i).*(3DES|\\bDES\\b|\\bRC4\\b|\\bAES128\\b|\\bAES-128\\b|aws:s3).*", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption at rest - Use AES-256 or stronger encryption for stored data. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == vpn_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i).*(3DES|\\bDES\\b|\\bRC4\\b|\\bMD5\\b|\\bSHA-?1\\b|\\bgroup1\\b|\\bgroup2\\b|ikev1).*", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak VPN/IPsec/IKE tunnel configuration - Avoid DES, 3DES, MD5, SHA-1, and weak DH groups. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cert_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i).*(\\bsha-?1\\b|\\bmd5\\b|sha1WithRSA|md5WithRSA).*", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure certificate or signing algorithm - Avoid SHA-1 and MD5 for certificate signing operations. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == policy_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i).*(2015|2016|FS-1-0|TLS-1-0|TLS-1-1|legacy|ELBSecurityPolicy-2015).*", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure predefined security policy - Legacy policies bundle weak cryptographic configurations. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == auth_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(md5|sha-?1|des|3des|rc4|rc2|null|plain|plaintext|crypt)$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak authentication method configured - Avoid MD5, SHA-1, and other broken algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "MethodCall"
    node.receiver.ir_type == "VariableReference"
    regex.match("(?i).*(\\bMD5\\b|\\bSHA-?1\\b|\\b3DES\\b|\\bRC4\\b|\\bRC2\\b)", node.receiver.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cryptographic algorithm used in method call - Avoid MD5, SHA-1, 3DES, RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, node])
    node.ir_type == "FunctionCall"
    arg := node.args[_]
    arg.ir_type == "String"
    regex.match("(?i)^(md5|sha-?1|des|3des|rc4|rc2)$", arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak hashing algorithm used as argument in function call - Avoid MD5, SHA-1, DES, RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, node])
    node.ir_type == "VariableReference"
    regex.match("(?i).*(md5|sha1|sha_1|3des|rc4)", node.value)
    regex.match("(?i).*(password|passwd|secret|auth|hash|digest|crypt|encrypt)", node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Attribute references variable using weak cryptographic algorithm in name. (CWE-327)"
    }
}