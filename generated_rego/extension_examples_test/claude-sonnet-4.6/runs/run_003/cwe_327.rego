package glitch

import data.glitch_lib

tls_attr_names := {"ssl_policy", "minimum_protocol_version", "tls_version", "security_policy", "protocol_version", "ssl_protocol", "min_tls_version", "tls_minimum_version"}

cipher_attr_names := {"cipher_suite", "cipher", "ssl_cipher", "cipher_algorithm", "encryption_algorithm", "allowed_algorithms", "ciphers", "cipher_suites"}

hash_attr_names := {"hash_algorithm", "digest_algorithm", "signing_algorithm", "integrity_algorithm", "hashing", "checksum_algorithm", "signature_algorithm", "digest_type", "certificate_algorithm", "key_algorithm", "encrypt", "auth_method"}

key_size_attr_names := {"key_size", "key_length", "rsa_bits", "key_bits", "modulus_length"}

mode_attr_names := {"mode", "cipher_mode", "encryption_mode", "block_mode"}

dh_attr_names := {"dh_group", "dh_param_size", "key_exchange_algorithm", "ecdh_curve", "pfs_group", "diffie_hellman_group"}

policy_attr_names := {"ssl_policy", "security_policy", "predefined_policy", "tls_policy", "listener_ssl_policy"}

weak_hash_regex := "(?i)(\\bMD[245]\\b|md[245]_crypt|\\bSHA-?1\\b|\\bCRC32\\b|sha1WithRSAEncryption|md5WithRSAEncryption)"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    tls_attr_names[attr.name]
    attr.value.ir_type == "String"
    regex.match("(?i)^(SSLv?[23]|TLSv?1(\\.[01]|_[01])?|TLS_1_[01])$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic protocol version. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    cipher_attr_names[attr.name]
    attr.value.ir_type == "String"
    regex.match("(?i)(\\bRC4\\b|\\bRC2\\b|\\bDES\\b|3DES|TRIPLE.?DES|TDEA|\\bNULL\\b|\\bEXPORT\\b|\\bANON\\b|\\bIDEA\\b|\\bSEED\\b|_SHA[^0-9]|_SHA$)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky encryption algorithm or cipher suite. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    hash_attr_names[attr.name]
    attr.value.ir_type == "String"
    regex.match(weak_hash_regex, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a deprecated or broken hash algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    key_size_attr_names[attr.name]
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient asymmetric key size. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    mode_attr_names[attr.name]
    attr.value.ir_type == "String"
    regex.match("(?i)(\\bECB\\b|ECB_MODE)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of ECB block cipher mode. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    dh_attr_names[attr.name]
    attr.value.ir_type == "String"
    regex.match("(?i)(\\bmodp768\\b|\\bmodp1024\\b|\\bGroup[125]\\b)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a weak Diffie-Hellman group. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    policy_attr_names[attr.name]
    attr.value.ir_type == "String"
    regex.match("(?i)(201[0-7]|\\blegacy\\b|\\bcompat(ibility)?\\b|backward.?compat)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a weak or legacy security policy. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    regex.match("(?i)filter[|]hash", node.name)
    arg := node.args[_]
    arg.ir_type == "String"
    regex.match(weak_hash_regex, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a deprecated hash function via filter. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    regex.match("(?i)^(md[245]|sha1|sha_1|crc32)$", node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Direct use of a deprecated or broken hash function. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    hash_attr_names[entry.key.value]
    entry.value.ir_type == "String"
    regex.match(weak_hash_regex, entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of a deprecated hash algorithm in configuration map. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match("(?i)(cipher_suite|ssl_cipher|cipher_algorithm)", v.name)
    v.value.ir_type == "String"
    regex.match("(?i)(\\bRC4\\b|\\bRC2\\b|\\bDES\\b|3DES|TRIPLE.?DES|TDEA|\\bNULL\\b|\\bEXPORT\\b|\\bANON\\b|\\bIDEA\\b|\\bSEED\\b|_SHA[^0-9]|_SHA$)", v.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a broken or risky encryption algorithm in variable. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Access"
    node.right.ir_type == "String"
    regex.match("(?i)(md[245]|sha.?1|crc32)", node.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Accessing a data field with a weak hash algorithm indicator in its name. (CWE-327)"
    }
}