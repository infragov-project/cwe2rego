package glitch

import data.glitch_lib

weak_hash_regex := "(?i)(md2|md4|md5|sha-1|sha1|sha_1|md5_crypt|des_crypt|sha256_crypt)"

weak_hash_func_regex := "(?i)^(md2|md4|md5|sha1|sha_1|sha-1|sha256|ripemd160)$"

weak_algo_regex := "(?i)^(DES|3DES|TDEA|RC2|RC4|RC5|Blowfish|IDEA|NULL)$"

weak_tls_regex := "(?i)(SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1|TLSv1[^\\d]|TLSv1$)"

dangerous_cipher_regex := "(?i)(EXPORT|aNULL|eNULL|RC4|\\bDES\\b|3DES|ANON|_SHA\\b)"

hash_attr_names := {"hash_algorithm", "signature_algorithm", "digest", "digest_algorithm", "hmac_algorithm", "checksum_algorithm", "encrypt", "auth_method"}

cipher_suite_attr_names := {"ssl_ciphers", "cipher_suites", "allowed_ciphers", "cipher_list", "preferred_cipher_suites"}

weak_algo_attr_names := {"algorithm", "encryption_algorithm", "cipher", "cipher_suite", "cipher_type", "encryption_type", "encryption_mode"}

tls_attr_names := {"tls_version", "minimum_tls_version", "ssl_protocols", "protocol", "listener_protocol", "frontend_protocol", "backend_protocol", "ssl_policy", "security_policy"}

key_size_attr_names := {"key_size", "key_length", "key_bits", "rsa_bits", "bit_length", "modulus_length", "rsa_key_size"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    regex.match(weak_hash_func_regex, node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cryptographic hash function called directly. Avoid md5(), sha1(). (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    regex.match("(?i)hash", node.name)
    arg := node.args[_]
    arg.ir_type == "String"
    regex.match(weak_hash_regex, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cryptographic hash algorithm detected in function call. Avoid MD5, SHA1. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    key := hash_attr_names[_]
    glitch_lib.contains(entry.key.value, key)
    entry.value.ir_type == "String"
    regex.match(weak_hash_regex, entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Weak cryptographic hash or encryption algorithm detected in nested configuration. Avoid MD5, SHA1, md5_crypt. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    key := cipher_suite_attr_names[_]
    glitch_lib.contains(node.name, key)
    node.value.ir_type == "String"
    regex.match(dangerous_cipher_regex, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak or dangerous cipher suite configuration detected. Avoid EXPORT, NULL, ANON, RC4, DES, SHA-1 based suites. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    key := weak_algo_attr_names[_]
    glitch_lib.contains(attr.name, key)
    attr.value.ir_type == "String"
    regex.match(weak_algo_regex, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak or deprecated encryption algorithm detected. Avoid DES, 3DES, RC4, RC2, Blowfish, IDEA, NULL. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    key := tls_attr_names[_]
    glitch_lib.contains(attr.name, key)
    attr.value.ir_type == "String"
    regex.match(weak_tls_regex, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak TLS/SSL protocol version detected. Avoid SSLv2, SSLv3, TLSv1.0, TLSv1.1. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    key := cipher_suite_attr_names[_]
    glitch_lib.contains(attr.name, key)
    attr.value.ir_type == "String"
    regex.match(dangerous_cipher_regex, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak or dangerous cipher suite configuration detected. Avoid EXPORT, NULL, ANON, RC4, DES, SHA-1 based suites. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    key := hash_attr_names[_]
    glitch_lib.contains(attr.name, key)
    attr.value.ir_type == "String"
    regex.match(weak_hash_regex, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cryptographic hash algorithm detected. Avoid MD2, MD4, MD5, SHA1, SHA-1. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Access"
    attr.value.right.ir_type == "String"
    regex.match(weak_hash_regex, attr.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cryptographic hash algorithm referenced in access key. Avoid MD5, SHA1. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    key := key_size_attr_names[_]
    glitch_lib.contains(attr.name, key)
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient cryptographic key size detected. RSA/DSA keys should be at least 2048 bits. (CWE-326)"
    }
}