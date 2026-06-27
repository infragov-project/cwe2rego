package glitch

import data.glitch_lib
import future.keywords.if

weak_password_crypto := {"md5_crypt", "crypt", "des_crypt", "sha1_crypt", "md5", "sha1", "des"}

weak_crypto_algorithms := {"DES", "3DES", "RC2", "RC4", "Blowfish", "CAST", "IDEA", "SEED", "ARIA", "MD5", "SHA1", "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLS1.0", "TLS1.1", "ECB", "NULL", "EXPORT", "ANON", "secp160", "secp192", "secp224", "brainpoolP160", "brainpoolP192", "prime192", "sect163", "HMAC-MD5", "HMAC-SHA1", "PBKDF1"}

weak_cipher_patterns := {"_CBC_", "CBC_SHA", "MD5", "SHA1", "SEED", "RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "RSA_WITH_AES"}

weak_hash_func_names := {"md5", "sha1", "hash", "encrypt"}

crypto_value_names := {"encrypt", "cipher", "crypto", "hash", "mode", "tls", "ssl", "algorithm", "protocol", "auth_method", "key_exchange", "kex_algorithm", "named_curve", "mac_algorithm", "hmac", "signature_algorithm"}

access_key_contains_weak_crypto(node) if {
    node.ir_type == "Access"
    node.right.ir_type == "String"
    key := node.right.value
    is_weak_algorithm(key)
}

access_key_contains_weak_crypto(node) if {
    node.ir_type == "Access"
    node.right.ir_type == "String"
    key := node.right.value
    weak_algo_in_access_key(key)
}

weak_algo_in_access_key(key) if {
    contains(lower(key), "md5")
    not contains(lower(key), "md5_")
}

weak_algo_in_access_key(key) if {
    contains(lower(key), "sha1")
}

weak_algo_in_access_key(key) if {
    contains(lower(key), "des")
    not contains(lower(key), "desired")
}

is_weak_algorithm(str) if {
    weak_crypto_algorithms[kw]
    upper(str) == upper(kw)
} else if {
    weak_crypto_algorithms[kw]
    regex.match(sprintf("(?i)\\b%s\\b", [kw]), str)
}

is_weak_password_crypto(str) if {
    weak_password_crypto[m]
    str == m
} else if {
    weak_password_crypto[m]
    regex.match(sprintf("(?i)\\b%s\\b", [m]), str)
}

has_weak_cipher_pattern(str) if {
    weak_cipher_patterns[p]
    regex.match(sprintf("(?i).*%s.*", [p]), str)
}

is_crypto_value_name(name) if {
    crypto_value_names[kw]
    regex.match(sprintf("(?i)^%s$", [kw]), name)
}

is_weak_hash_func_name(name) if {
    weak_hash_func_names[f]
    regex.match(sprintf("(?i)\\b%s\\b", [f]), name)
}

contains(str, substr) if {
    regex.match(sprintf("(?i).*%s.*", [substr]), str)
}

lower(str) = result if {
    result := lower(str)
}

get_leaf_nodes(node) = nodes if {
    node.ir_type == "Array"
    nodes := {n | some v; n := get_leaf_nodes(v); v := node.value[_]}
} else if {
    node.ir_type == "Hash"
    nodes := {n | some pair; pair := node.value[_]; n := get_leaf_nodes(pair.value)}
} else if {
    {"String", "Integer"}[node.ir_type]
    nodes := {node}
} else if {
    {"Access", "VariableReference", "FunctionCall", "MethodCall"}[node.ir_type]
    nodes := {node}
} else {
    nodes := set()
}

string_from_node(node) = node.value if {
    node.ir_type == "String"
}

string_from_node(node) = node.value if {
    node.ir_type == "VariableReference"
}

string_from_node(node) = node.right.value if {
    node.ir_type == "Access"
    node.right.ir_type == "String"
}

traverse_for_weak_crypto(node, parent_elem, parent_path, result) if {
    node.ir_type == "Hash"
    some pair
    pair.key.ir_type == "String"
    pair.key.value == "encrypt"
    pair.value.ir_type == "String"
    is_weak_password_crypto(pair.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": pair.value,
        "path": parent_path,
        "description": "Inadequate Encryption Strength - Use of weak password hashing/encryption method detected. (CWE-326)"
    }
}

traverse_for_weak_crypto(node, parent_elem, parent_path, result) if {
    node.ir_type == "Hash"
    some pair
    pair.key.ir_type == "String"
    is_crypto_value_name(pair.key.value)
    pair.value.ir_type == "String"
    is_weak_algorithm(pair.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": pair.value,
        "path": parent_path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in configuration. (CWE-326)"
    }
}

traverse_for_weak_crypto(node, parent_elem, parent_path, result) if {
    node.ir_type == "Hash"
    some pair
    pair.key.ir_type == "String"
    is_crypto_value_name(pair.key.value)
    pair.value.ir_type == "String"
    has_weak_cipher_pattern(pair.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": pair.value,
        "path": parent_path,
        "description": "Inadequate Encryption Strength - Use of weak cipher suite detected. (CWE-326)"
    }
}

traverse_for_weak_crypto(node, parent_elem, parent_path, result) if {
    node.ir_type == "Hash"
    some pair
    pair.key.ir_type == "String"
    pair.key.value == "salt_size"
    pair.value.ir_type == "Integer"
    pair.value.value < 16
    pair.value.value > 0
    result := {
        "type": "sec_weak_crypt",
        "element": pair.value,
        "path": parent_path,
        "description": "Inadequate Encryption Strength - Weak salt size (less than 16 bits). (CWE-326)"
    }
}

traverse_for_weak_crypto(node, parent_elem, parent_path, result) if {
    node.ir_type == "FunctionCall"
    arg := node.args[_]
    arg.ir_type == "String"
    is_weak_algorithm(arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent_path,
        "description": "Inadequate Encryption Strength - Function call uses weak cryptographic algorithm. (CWE-326)"
    }
}

traverse_for_weak_crypto(node, parent_elem, parent_path, result) if {
    node.ir_type == "FunctionCall"
    is_weak_hash_func_name(node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent_path,
        "description": "Inadequate Encryption Strength - Use of weak hash algorithm. (CWE-326)"
    }
}

traverse_for_weak_crypto(node, parent_elem, parent_path, result) if {
    node.ir_type == "Attribute"
    is_crypto_value_name(node.name)
    val := node.value
    val.ir_type == "String"
    is_weak_algorithm(val.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent_path,
        "description": "Inadequate Encryption Strength - Use of weak cryptographic algorithm. (CWE-326)"
    }
}

traverse_for_weak_crypto(node, parent_elem, parent_path, result) if {
    node.ir_type == "Attribute"
    is_crypto_value_name(node.name)
    val := node.value
    val.ir_type == "String"
    has_weak_cipher_pattern(val.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent_path,
        "description": "Inadequate Encryption Strength - Use of weak cipher suite. (CWE-326)"
    }
}

traverse_for_weak_crypto(node, parent_elem, parent_path, result) if {
    node.ir_type == "Attribute"
    node.name == "password"
    access_key_contains_weak_crypto(node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": access_node
        "path": parent_path,
        "description": "Inadequate Encryption Strength - Password attribute accesses weak crypto reference. (CWE-326)"
    }
    access_node := node.value
}

traverse_for_weak_crypto(node, parent_elem, parent_path, result) if {
    node.ir_type == "Variable"
    is_crypto_value_name(node.name)
    val := node.value
    val.ir_type == "String"
    has_weak_cipher_pattern(val.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent_path,
        "description": "Inadequate Encryption Strength - Use of weak cipher suite in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    
    res := traverse_for_weak_crypto(node, parent, parent.path, result)
}