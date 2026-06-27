package glitch

import data.glitch_lib
import future.keywords.in

weak_algorithms := {"des", "3des", "rc4", "md5", "sha1", "sha-1", "blowfish", "ecb", "cbc", "md5_crypt", "sha1_crypt", "password_md5", "md5crypt", "sha1crypt"}

weak_tls_versions := {"tlsv1.0", "tlsv1.1", "sslv3", "sslv2", "1.0", "1.1"}

hash_function_names := {"filter|hash", "filter|md5", "filter|sha1", "hash", "md5", "sha1"}

encryption_keywords := {"algorithm", "cipher", "encryption", "crypto", "encrypt", "hash", "kms_key_spec", "block_cipher_mode", "hash_algorithm", "signature_algorithm", "public_key_algorithm", "signing_algorithm", "key_algorithm", "sse_algorithm", "encryption_at_rest", "storage_encrypted", "kms_key_id", "kms_master_key_id", "tls_version", "ssl_policy", "protocol", "cipher_suite", "cipher_suites", "security_policy", "min_tls_version", "ssl_certificate_id", "policy_name", "supported_protocols", "storage_encryption", "backup_retention", "snapshot_encryption", "password", "secret", "token", "api_key", "auth_method", "authentication", "encryption_options", "cipher_suites"}

key_size_keywords := {"key_size", "key_length", "key_bits", "modulus", "rsa_key_size", "aes_key_size", "minimum_tls_version", "key_spec", "validity_period", "password_length", "salt_size"}

lowercase(s) := lower(s)

is_weak_algorithm_str(s) {
    alg := weak_algorithms[_]
    lowercase(s) == alg
}

has_weak_algorithm_in_string(s) {
    alg := weak_algorithms[_]
    contains(lowercase(s), alg)
}

is_weak_tls_version(value) {
    value.ir_type == "String"
    ver := lowercase(value.value)
    v := weak_tls_versions[_]
    ver == v
}

is_small_key_size(value) {
    value.ir_type == "Integer"
    value.value < 2048
}

has_encryption_keyword_in_string(s) {
    key := encryption_keywords[_]
    contains(lowercase(s), key)
}

is_key_size_related(name) {
    key := key_size_keywords[_]
    contains(lowercase(name), key)
}

is_hash_function(name) {
    fname := lowercase(name)
    hf := hash_function_names[_]
    fname == hf
}

has_weak_crypto_in_string(value) {
    value.ir_type == "String"
    has_weak_algorithm_in_string(value.value)
}

has_weak_crypto_in_access(value) {
    value.ir_type == "Access"
    value.right.ir_type == "String"
    has_weak_algorithm_in_string(value.right.value)
}

contains_weak_crypto_value(val) {
    has_weak_crypto_in_string(val)
} else {
    has_weak_crypto_in_access(val)
} else {
    val.ir_type == "FunctionCall"
    is_hash_function(val.name)
    some arg in val.args
    arg.ir_type == "String"
    has_weak_algorithm_in_string(arg.value)
}

check_all_nodes_1(node) = result {
    node.ir_type == "String"
    has_weak_algorithm_in_string(node.value)
    result := {"type": "sec_weak_crypt", "element": node, "description": "Inadequate Encryption Strength - Weak cryptographic algorithm detected in string value. (CWE-326)"}
}

check_all_nodes_2(node) = result {
    node.ir_type == "Attribute"
    has_encryption_keyword_in_string(node.name)
    contains_weak_crypto_value(node.value)
    result := {"type": "sec_weak_crypt", "element": node, "description": "Inadequate Encryption Strength - Weak cryptographic algorithm, TLS version, or insecure mode detected in attribute. (CWE-326)"}
}

check_all_nodes_3(node) = result {
    node.ir_type == "Attribute"
    is_key_size_related(node.name)
    is_small_key_size(node.value)
    result := {"type": "sec_weak_crypt", "element": node, "description": "Inadequate Encryption Strength - Insufficient key size detected. (CWE-326)"}
}

check_all_nodes_4(node) = result {
    node.ir_type == "Variable"
    has_encryption_keyword_in_string(node.name)
    contains_weak_crypto_value(node.value)
    result := {"type": "sec_weak_crypt", "element": node, "description": "Inadequate Encryption Strength - Weak cryptographic algorithm detected in variable. (CWE-326)"}
}

check_all_nodes_5(node) = result {
    node.ir_type == "Variable"
    is_key_size_related(node.name)
    is_small_key_size(node.value)
    result := {"type": "sec_weak_crypt", "element": node, "description": "Inadequate Encryption Strength - Insufficient key size in variable. (CWE-326)"}
}

check_all_nodes_6(node) = result {
    node.ir_type == "FunctionCall"
    is_hash_function(node.name)
    some arg in node.args
    arg.ir_type == "String"
    has_weak_algorithm_in_string(arg.value)
    result := {"type": "sec_weak_crypt", "element": node, "description": "Inadequate Encryption Strength - Weak hash algorithm used in function call. (CWE-326)"}
}

check_hash_pairs_1(node) = result {
    node.ir_type == "Hash"
    some pair in node.value
    pair.key.ir_type == "String"
    has_encryption_keyword_in_string(pair.key.value)
    contains_weak_crypto_value(pair.value)
    result := {"type": "sec_weak_crypt", "element": pair, "description": "Inadequate Encryption Strength - Weak cryptographic algorithm detected in hash entry. (CWE-326)"}
}

check_hash_pairs_2(node) = result {
    node.ir_type == "Hash"
    some pair in node.value
    pair.value.ir_type == "String"
    is_weak_algorithm_str(pair.value.value)
    result := {"type": "sec_weak_crypt", "element": pair, "description": "Inadequate Encryption Strength - Weak cryptographic algorithm detected in hash value. (CWE-326)"}
}

check_array_hash_pairs_1(node) = result {
    node.ir_type == "Array"
    some elem in node.value
    elem.ir_type == "Hash"
    hp := [check_hash_pairs_1(elem), check_hash_pairs_2(elem)][_]
    hp != null
    result := hp
}

check_all_funcs := [check_all_nodes_1, check_all_nodes_2, check_all_nodes_3, check_all_nodes_4, check_all_nodes_5, check_all_nodes_6]

check_hash_funcs := [check_hash_pairs_1, check_hash_pairs_2]

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some [_, node] in walk(parent)
    
    check := check_all_funcs[_](node)
    result := object.union(check, {"path": parent.path})
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some [_, node] in walk(parent)
    
    check := check_hash_funcs[_](node)
    result := object.union(check, {"path": parent.path})
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some [_, node] in walk(parent)
    
    check := check_array_hash_pairs_1(node)
    result := object.union(check, {"path": parent.path})
}