package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match("(?i)(algorithm|cipher|sse_algorithm|kms_key_algorithm|hash_algorithm|digest_algorithm|signing_algorithm|signature_algorithm|certificate_algorithm|encryption_type|integrity_algorithm|dh_group|pfs_group)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(DES|3DES|RC2|RC4|RC5|MD5|SHA-?1|IDEA|Blowfish|TEA|MD4|RIPEMD|HMAC-MD5|HMAC-SHA1|sha1WithRSAEncryption|md5WithRSAEncryption|AES128|group1|group2|group5)$", attr.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match("(?i)(min_protocol_version|minimum_protocol_version|ssl_protocol|protocol_version|tls_version|ssl_version|enabled_protocols|allowed_protocols|supported_protocols|ssl_policy|security_policy|tls_policy)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)(SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1|^TLSv1$|^1\\.0$|^1\\.1$)", attr.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of insecure TLS/SSL protocol version - Avoid enabling deprecated TLS/SSL protocol versions. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match("(?i)(cipher_suites|allowed_ciphers|enabled_ciphers|cipher_list|cipher_preference|custom_cipher_policy)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)(NULL|EXPORT|ANON|RC4|\\bDES\\b|3DES|\\bMD5\\b|aNULL|eNULL)", attr.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cipher suite - Avoid enabling cipher suites with known weaknesses such as NULL, EXPORT, RC4, DES or MD5. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match("(?i)(key_size|key_length|key_bits|rsa_bits|modulus_length|dh_param_bits)", attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value < 2048

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient cryptographic key length - Key sizes below 2048 bits are considered insecure for RSA and DSA. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match("(?i)(^encrypt$|encryption_enabled|storage_encrypted|encryption_at_rest_enabled)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption is explicitly disabled - Sensitive resources must always have encryption enabled. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match("(?i)(insecure_ssl|disable_tls_validation|insecure_transport)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure transport or TLS validation bypass is enabled - This undermines cryptographic protections in transit. (CWE-327)"
    }
}