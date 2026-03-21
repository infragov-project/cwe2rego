package glitch

import data.glitch_lib

crypto_attr_names := {
    "algorithm", "cipher", "encryption_algorithm", "cipher_suite",
    "hash_algorithm", "digest_algorithm", "signature_algorithm",
    "key_spec", "key_algorithm", "block_cipher_mode", "ssl_ciphers",
    "signing_algorithm", "digest_method", "integrity_algorithm",
    "hmac_algorithm", "token_algorithm", "checksum_algorithm"
}

tls_attr_names := {
    "minimum_protocol_version", "min_tls_version", "ssl_protocol",
    "ssl_policy", "protocol_version", "security_policy",
    "tls_profile", "predefined_ssl_policy", "cipher_policy"
}

key_size_attr_names := {
    "key_size", "key_length", "key_bits", "rsa_bits",
    "modulus_length", "bit_length", "key_strength"
}

enc_toggle_attr_names := {
    "encryption_enabled", "encrypt_at_rest", "storage_encrypted",
    "encrypt_in_transit", "transit_encryption", "kms_encrypted"
}

weak_algo_pattern := "(?i).*(\\bdes\\b|\\b3des\\b|tripledes|\\brc2\\b|\\brc4\\b|\\brc5\\b|\\bidea\\b|blowfish|\\becb\\b|\\btea\\b|\\bxtea\\b|\\bmd2\\b|\\bmd4\\b|\\bmd5\\b|\\bsha.?1\\b|ripemd|\\bnull\\b|\\bexport\\b|\\banon\\b|\\badh\\b|\\baecdh\\b|sha1withrsa|md5withrsa|rsa_pkcs1_sha1|ecdsa_sha1|secp112r1|secp128r1|\\bprng\\b|insecure_random|pseudo_random).*"

deprecated_tls_pattern := "(?i).*(sslv2|sslv3|ssl_v2|ssl_v3|tlsv1[._]0|tlsv1[._]1|tls1[._]0|tls1[._]1|\\b2015\\b|\\b2016\\b|\\blegacy\\b|\\bcompat\\b|\\bcompatible\\b).*"

weak_key_sizes := {40, 56, 64, 160, 192, 512, 768, 1024}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == crypto_attr_names[_]
    attr.value.ir_type == "String"
    regex.match(weak_algo_pattern, attr.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or deprecated cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == tls_attr_names[_]
    attr.value.ir_type == "String"
    regex.match(deprecated_tls_pattern, attr.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of deprecated TLS/SSL protocol version or legacy security policy - Use TLS 1.2 or higher. (CWE-327)"
    }
}

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
        "description": "Insufficient cryptographic key length - Use key sizes that meet current security standards. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == enc_toggle_attr_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption is disabled - Ensure encryption is enabled for data at rest and in transit. (CWE-327)"
    }
}