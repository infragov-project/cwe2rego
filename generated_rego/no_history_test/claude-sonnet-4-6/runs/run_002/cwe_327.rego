package glitch

import data.glitch_lib

crypto_fields := {
    "encryption_algorithm", "cipher", "cipher_suite", "cipher_algorithm",
    "algorithm", "crypto_algorithm", "encryption_type", "hash_algorithm",
    "digest_algorithm", "signing_algorithm", "certificate_algorithm",
    "integrity_algorithm", "checksum_algorithm", "signature_algorithm",
    "auth_algorithm", "authentication_protocol", "wifi_security",
    "encryption_mode", "phase1_encryption_algorithms", "phase2_encryption_algorithms",
    "phase1_integrity_algorithms", "phase2_integrity_algorithms", "key_algorithm",
    "encrypt", "digest", "ssl_ciphers", "enabled_ciphers", "cipher_suites",
    "allowed_ciphers", "ssl_protocols", "minimum_protocol_version",
    "minimum_tls_version", "tls_version", "security_policy", "ssl_policy",
    "protocol_version", "tls_policy", "ike_versions", "predefined_policy",
    "listener_policy", "tls_cipher_policy", "key_spec", "customer_master_key_spec",
    "dh_group", "pfs_group", "auth_method", "password"
}

weak_algo_regex := "(?i)(\\bdes\\b|\\b3des\\b|\\brc4\\b|\\brc2\\b|\\brc5\\b|md5|sha-1|sha1|\\bsslv2\\b|\\bsslv3\\b|tlsv1\\.0|tlsv1\\.1|\\bssl20\\b|\\bssl30\\b|\\btls10\\b|\\btls11\\b|\\bexport\\b|anull|enull|\\badh\\b|\\baecdh\\b|rsa_1024|rsa_768|rsa_512|\\bgroup1\\b|\\bgroup2\\b|modp1024|legacy|deprecated|\\bntlm\\b|\\bwep\\b|\\btkip\\b|\\bpap\\b|\\bchap\\b|_sha[^0-9a-zA-Z]|_sha$)"

weak_func_names := {"md5", "sha1", "sha", "rc4", "des", "crc32", "hmac_md5", "hmac_sha1", "blowfish"}

name_has_crypto_field(name) {
    field := crypto_fields[_]
    glitch_lib.contains(name, field)
}

value_is_weak(str) {
    regex.match(weak_algo_regex, str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    name_has_crypto_field(attr.name)
    walk(attr.value, [_, str_node])
    str_node.ir_type == "String"
    value_is_weak(str_node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using deprecated or weak algorithms such as DES, RC4, MD5, or SHA1. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    name_has_crypto_field(v.name)
    walk(v.value, [_, str_node])
    str_node.ir_type == "String"
    value_is_weak(str_node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using deprecated or weak algorithms such as DES, RC4, MD5, or SHA1. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    walk(v.value, [_, func_node])
    func_node.ir_type == "FunctionCall"
    lower(func_node.name) == weak_func_names[_]
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm via function call - Avoid using deprecated or weak algorithms such as MD5 or SHA1. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, func_node])
    func_node.ir_type == "FunctionCall"
    lower(func_node.name) == weak_func_names[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm via function call - Avoid using deprecated or weak algorithms such as MD5 or SHA1. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "key_size"
    attr.value.ir_type == "Integer"
    attr.value.value > 0
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length - Asymmetric keys should be at least 2048 bits. (CWE-327)"
    }
}