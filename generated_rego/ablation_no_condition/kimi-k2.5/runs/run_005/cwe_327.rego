package glitch

import data.glitch_lib

weak_algorithms := {"des", "3des", "tripledes", "md4", "md5", "sha0", "sha1", "rc4", "rc2", "blowfish", "tea", "xtea", "seed", "idea", "cast", "cast5", "cast6", "skipjack", "dh", "dsa", "ecdsa", "rsa-1024", "rsa1024", "aes-128-ecb", "aes128ecb", "aes-192-ecb", "aes192ecb", "aes-256-ecb", "aes256ecb", "des-ecb", "desecb", "3des-ecb", "3desecb", "tripledes-ecb", "tripledesecb", "rc4-40", "rc440", "rc4-56", "rc456", "rc2-40", "rc240", "rc2-56", "rc256", "blowfish-ecb", "blowfishecb", "xor", "rot13", "rot25", "rot47", "ecb", "cbc", "cfb", "ofb"}

crypto_config_keys := {"algorithm", "cipher", "encrypt", "hash", "digest", "checksum", "signature", "mac", "kex", "key_exchange", "ssl_version", "tls_version", "min_version", "max_version", "cipher_suites", "ciphers", "tls_policy", "ssl_policy", "encryption_algorithm", "hash_algorithm", "signature_algorithm", "mac_algorithm", "kex_algorithm", "key_algorithm", "crypto_algorithm", "protocol", "auth_method", "encrypt_method", "hash_method", "digest_method", "checksum_method", "cipher_suite", "store_type", "encryption", "signing_algorithm", "asymmetric_encryption", "password"}

contains_weak_algorithm(s) {
    lower_s := lower(s)
    alg := weak_algorithms[_]
    contains(lower_s, alg)
}

is_crypto_config_key(s) {
    lower_key := lower(trim(s, "'\""))
    ck := crypto_config_keys[_]
    lower_key == ck
}

is_crypto_config_key(s) {
    lower_key := lower(trim(s, "'\""))
    regex.match(".*(cipher|encrypt|hash|digest|ssl|tls|kex|signature|mac|algorithm|protocol|password).*", lower_key)
}

has_crypto_config_key_in_name(s) {
    lower_s := lower(s)
    ck := crypto_config_keys[_]
    contains(lower_s, ck)
}

get_string_value(node) = val {
    node.ir_type == "String"
    val := node.value
} else = val {
    node.ir_type == "VariableReference"
    val := node.value
}

any_node_contains_weak_algorithm(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    contains_weak_algorithm(n.value)
}

check_access_for_weak_crypto(node) {
    node.ir_type == "Access"
    node.right.ir_type == "String"
    contains_weak_algorithm(node.right.value)
}

check_access_for_weak_crypto(node) {
    node.ir_type == "Access"
    node.right.ir_type == "String"
    has_crypto_config_key_in_name(node.right.value)
    node.left.ir_type == "VariableReference"
    contains_weak_algorithm(node.left.value)
}

check_value_for_weak_crypto(node) {
    val := get_string_value(node)
    contains_weak_algorithm(val)
}

check_value_for_weak_crypto(node) {
    any_node_contains_weak_algorithm(node)
}

check_value_for_weak_crypto(node) {
    check_access_for_weak_crypto(node)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Variable"
    has_crypto_config_key_in_name(node.name)
    check_value_for_weak_crypto(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, broken, or deprecated cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    is_crypto_config_key(node.name)
    check_value_for_weak_crypto(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, broken, or deprecated cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    is_crypto_config_key(entry.key.value)
    check_value_for_weak_crypto(entry.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": entry,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, broken, or deprecated cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    node.name == "password"
    check_access_for_weak_crypto(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, broken, or deprecated cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "FunctionCall"
    lower_name := lower(trim(node.name, "'\""))
    alg := weak_algorithms[_]
    contains(lower_name, alg)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, broken, or deprecated cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "FunctionCall"
    alg := weak_algorithms[_]
    arg := node.args[_]
    arg.ir_type == "String"
    contains(lower(arg.value), alg)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, broken, or deprecated cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "MethodCall"
    lower_method := lower(trim(node.method, "'\""))
    alg := weak_algorithms[_]
    contains(lower_method, alg)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, broken, or deprecated cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "MethodCall"
    alg := weak_algorithms[_]
    arg := node.args[_]
    arg.ir_type == "String"
    contains(lower(arg.value), alg)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, broken, or deprecated cryptographic algorithms. (CWE-327)"
    }
}