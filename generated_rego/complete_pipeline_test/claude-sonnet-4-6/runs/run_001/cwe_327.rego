package glitch

import data.glitch_lib

crypto_name_set := {
    "algorithm", "cipher", "cipher_suites", "cipher_suite", "ciphers",
    "encrypt", "encryption", "signing_algorithm", "hash_algorithm",
    "digest_algorithm", "integrity_algorithm", "checksum_algorithm",
    "hash_type", "signature_algorithm", "sse_algorithm",
    "cipher_mode", "block_mode", "encryption_mode", "macs",
    "mac_algorithms", "ssl_policy", "tls_policy", "min_tls_version",
    "minimum_protocol_version", "security_policy", "ssl_protocol",
    "protocol_version", "tls_version", "dh_group", "pfs_group",
    "encryption_algorithms", "integrity_algorithms", "key_algorithm",
    "kms_key_algorithm", "crypto_algorithm", "kms_key_spec", "key_spec",
    "auth_method", "authentication_method"
}

weak_crypto_regex := "(?i)(\\bDES\\b|\\b3DES\\b|\\bRC2\\b|\\bRC4\\b|\\bRC5\\b|\\bBLOWFISH\\b|\\bMD4\\b|md5|sha1|sha-1|sha_1|sha1with|md5with|rsa_1024|rsa_512|\\bECB\\b|arcfour|cast128|hmac-md5|hmac-sha1|\\bGROUP1\\b|\\bGROUP2\\b|MODP768|MODP1024|SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1|TLS_1_0|TLS_1_1|_CBC_SHA[^2-9]|_CBC_SHA$)"

weak_algo_exact_regex := "(?i)^(md5|sha1|sha-1|sha_1|des|3des|triple_des|rc2|rc4|rc5|blowfish|md4|md2|idea|tea|md5_crypt|des_crypt|arcfour)$"

weak_func_name_regex := "(?i)^(md5|sha1|sha_1|des_encrypt|rc4_encrypt|blowfish_encrypt|md4|crc32)$"

weak_access_key_regex := "(?i)(_(md5|sha1|sha_1|sha-1|des|rc4)$|^(md5|sha1|sha-1|des|rc4)_)"

name_matches_crypto(name) {
    kw := crypto_name_set[_]
    glitch_lib.contains(name, kw)
}

value_is_weak(str_value) {
    regex.match(weak_crypto_regex, str_value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    name_matches_crypto(attr.name)
    attr.value.ir_type == "String"
    value_is_weak(attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Replace with secure modern alternatives such as AES-256, SHA-256, or TLS 1.2+. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    name_matches_crypto(v.name)
    v.value.ir_type == "String"
    value_is_weak(v.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Replace with secure modern alternatives such as AES-256, SHA-256, or TLS 1.2+. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match(weak_algo_exact_regex, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Replace with secure modern alternatives such as AES-256, SHA-256, or TLS 1.2+. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    pair.key.ir_type == "String"
    name_matches_crypto(pair.key.value)
    pair.value.ir_type == "String"
    value_is_weak(pair.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": pair.value,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Replace with secure modern alternatives such as AES-256, SHA-256, or TLS 1.2+. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    pair.key.ir_type == "String"
    name_matches_crypto(pair.key.value)
    pair.value.ir_type == "String"
    regex.match(weak_algo_exact_regex, pair.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": pair.value,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Replace with secure modern alternatives such as AES-256, SHA-256, or TLS 1.2+. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    regex.match(weak_func_name_regex, node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Replace with secure modern alternatives such as AES-256, SHA-256, or TLS 1.2+. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    regex.match("(?i)(hash|digest|hmac|crypt|encrypt|sign)", node.name)
    arg := node.args[_]
    arg.ir_type == "String"
    value_is_weak(arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Replace with secure modern alternatives such as AES-256, SHA-256, or TLS 1.2+. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "Access"
    node.value.right.ir_type == "String"
    regex.match(weak_access_key_regex, node.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Replace with secure modern alternatives such as AES-256, SHA-256, or TLS 1.2+. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(encrypted|storage_encrypted|encrypt_at_rest|enable_encryption|enable_https|force_ssl|require_ssl)", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption is explicitly disabled - Enable strong encryption to protect data at rest and in transit. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(key_size|key_length|rsa_bits)", attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cryptographic key size detected - Use at least 2048 bits for RSA/DH. (CWE-327)"
    }
}