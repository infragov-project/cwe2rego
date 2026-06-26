package glitch

import data.glitch_lib

weak_cipher_fields := {"cipher", "cipher_suite", "cipher_list", "ssl_cipher", "encryption_algorithm", "encryption_type", "server_side_encryption", "kms_key_algorithm", "storage_encryption_algorithm", "disk_encryption_algorithm", "encryption_mode", "encryption_spec", "encryption_standard"}

weak_hash_fields := {"hash_algorithm", "digest_algorithm", "signing_algorithm", "integrity_algorithm", "checksum_type", "signature_algorithm", "cert_hash_algorithm", "hmac_algorithm", "password_encryption", "hash_type", "password_hash", "cert_algorithm", "signing_hash", "certificate_hash"}

weak_tls_fields := {"ssl_policy", "tls_policy", "min_protocol_version", "max_protocol_version", "ssl_protocols", "tls_version", "protocol_version", "minimum_tls_version", "ssl_minimum_version"}

bypass_fields := {"enforce_https", "require_ssl", "force_ssl", "encryption_enforced", "ssl_enforcement_enabled", "require_encrypted_endpoints", "allow_downgrade", "disable_encryption", "plaintext_allowed", "insecure_ssl", "allow_insecure", "disable_tls_validation"}

weak_key_fields := {"key_size", "key_length", "rsa_bits", "modulus_length", "key_bits", "bit_strength"}

weak_ssh_fields := {"kex_algorithms", "macs", "host_key_algorithms", "ciphers", "pubkey_accepted_algorithms"}

weak_vpn_fields := {"phase1_encryption", "phase2_encryption", "ipsec_policy", "vpn_encryption", "authentication_algorithm", "ike_policy", "encryption_algorithms", "integrity_algorithms"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_cipher_fields[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(\\bDES\\b|\\b3DES\\b|TRIPLE_DES|\\bRC2\\b|\\bRC4\\b|\\bRC5\\b|ARCFOUR|BLOWFISH|\\bIDEA\\b|\\bSEED\\b|\\bEXPORT\\b|eNULL|aNULL|_ECB\\b|\\bECB_)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak or deprecated cipher algorithm detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_hash_fields[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(\\bMD2\\b|\\bMD4\\b|\\bMD5\\b|\\bSHA-?1\\b|\\bSHA_1\\b|RIPEMD-?160|MD5withRSA|SHA1withRSA|\\bcrypt\\b|md5crypt)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak or broken hashing algorithm detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_tls_fields[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(SSLv?2|SSLv?3|TLSv?1\\.0|TLSv?1\\.1|TLS1_0|TLS1_1|TLS_1_0|TLS_1_1|\\bSSL2\\b|\\bSSL3\\b|\\bTLSv1\\b)", attr.value.value)
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
    attr.name == bypass_fields[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Encryption enforcement disabled, allowing plaintext transmission or downgrade attacks. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == bypass_fields[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(false|disabled|none|no)$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Encryption enforcement disabled, allowing plaintext transmission or downgrade attacks. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_key_fields[_]
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak asymmetric key length detected (less than 2048 bits). (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_ssh_fields[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(arcfour|aes128-cbc|3des-cbc|blowfish-cbc|hmac-md5|hmac-sha1|hmac-ripemd160|diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|gss-group1-sha1)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak SSH cipher, MAC, or key exchange algorithm detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_vpn_fields[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(\\bdes\\b|\\b3des\\b|\\bmd5\\b|\\bsha1\\b|hmac-md5|hmac-sha1|\\baes-128\\b)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak VPN/IPSec encryption or integrity algorithm detected. (CWE-327)"
    }
}