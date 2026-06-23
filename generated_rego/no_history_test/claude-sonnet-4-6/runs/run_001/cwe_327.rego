package glitch

import data.glitch_lib

crypto_attr_names := {
    "algorithm", "encryption_algorithm", "cipher", "cipher_suite",
    "hash_algorithm", "hashing_algorithm", "digest_algorithm", "signing_algorithm",
    "integrity_algorithm", "authentication_algorithm", "auth_method",
    "ssl_policy", "security_policy", "tls_policy",
    "minimum_tls_version", "min_tls_version", "tls_version", "ssl_version",
    "protocol", "protocols", "ssl_protocol", "https_protocol",
    "sse_algorithm", "checksum_type", "hmac_algorithm",
    "key_algorithm", "key_type", "certificate_algorithm",
    "ciphers", "macs", "kex_algorithms",
    "allowed_cipher_suites", "cipher_suites", "enabled_cipher_suites",
    "ssl_ciphers", "tls_ciphers",
    "phase1_encryption_algorithms", "phase2_encryption_algorithms",
    "phase1_integrity_algorithms", "phase2_integrity_algorithms",
    "encryption_type", "encryption_mode",
    "minimum_protocol_version", "origin_ssl_protocols",
    "encrypt", "password_hash", "password_encryption"
}

weak_algo_pattern := "(?i)(3DES|TripleDES|RC4|RC2|RC5|Blowfish|ECB|MD4|MD5|SHA1|SHA-1|CRC32|SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1|TLS_1_0|TLS_1_1|TLSv1_2016|SHA1WITH|MD5WITH|arcfour|blowfish-cbc|3des-cbc|hmac-md5|hmac-sha1|diffie-hellman-group1|EXPORT|ANON|ADH|MODP-768|MODP-1024|RSA_1024|(?:^|[^A-Za-z0-9])DES(?:[^A-Za-z0-9]|$)|(?:^|[^A-Za-z0-9])TLSv1(?:[^A-Za-z0-9]|$))"

weak_func_pattern := "(?i)^(md4|md5|sha1|sha|des_encrypt|rc4|crc32|blowfish_encrypt)$"

weak_name_segment_pattern := "(?i)(^|[^a-zA-Z0-9])(md4|md5|sha1|rc4|rc2|3des|tripledes|blowfish|arcfour|crc32)([^a-zA-Z0-9]|$)"

key_size_attr_names := {"key_size", "key_length", "rsa_bits", "key_bits"}
dh_group_attr_names := {"dh_group", "diffie_hellman_group", "pfs_group"}
weak_dh_groups := {1, 2, 5}

attr_name_matches_crypto(name) {
    attr_key := crypto_attr_names[_]
    regex.match(sprintf("(?i).*%s.*", [attr_key]), name)
}

is_weak_string(val) {
    val.ir_type == "String"
    regex.match(weak_algo_pattern, val.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr_name_matches_crypto(attr.name)
    is_weak_string(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr_name_matches_crypto(attr.name)
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    is_weak_string(elem)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm in array. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    attr_name_matches_crypto(v.name)
    is_weak_string(v.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm in variable. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    v.value.ir_type == "FunctionCall"
    regex.match(weak_func_pattern, v.value.name)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic function in variable assignment. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(weak_name_segment_pattern, v.name)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Variable name indicates use of a broken or risky cryptographic algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Access"
    attr.value.right.ir_type == "String"
    regex.match(weak_name_segment_pattern, attr.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Access key indicates use of a broken or risky cryptographic algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == key_size_attr_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value > 0
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Key size below 2048 bits detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == dh_group_attr_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value == weak_dh_groups[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak Diffie-Hellman group detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == dh_group_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(MODP-768|MODP-1024|group1|group2|group5)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak Diffie-Hellman group detected. (CWE-327)"
    }
}