package glitch

import data.glitch_lib

weak_algorithm_patterns = {"(?i)DES", "(?i)3DES", "(?i)RC4", "(?i)AES[-_]128", "(?i)SHA[-_]?1", "(?i)MD5", "(?i)md5_crypt"}
weak_protocol_patterns = {"(?i)SSLv3", "(?i)TLS[ _]?1[._]0", "(?i)TLS[ _]?1[._]1"}
weak_mode_patterns = {"(?i)ECB"}
key_size_threshold = 2048
aes_key_threshold = 256
iteration_threshold = 10000

crypto_name_pattern = "(?i)(algorithm|cipher|encrypt|decrypt|crypto|key|ssl|tls|hash|digest|md5|sha|des|rc4|aes|rsa|ecdsa|mode|protocol|iteration|salt|key_size|key_length|bits|strength|ssl_version|tls_version|protocol_version|min_protocol_version|block_mode|initialization_vector|key_rotation|reuse_keys|static_key|predefined_key|hash_algorithm|pbkdf2_iterations)"

check_crypto_name(name) {
    regex.match(crypto_name_pattern, name)
}

check_weak_algorithm(value) {
    value.ir_type == "String"
    regex.match(weak_algorithm_patterns[_], value.value)
}

check_weak_protocol(value) {
    value.ir_type == "String"
    regex.match(weak_protocol_patterns[_], value.value)
}

check_weak_mode(value) {
    value.ir_type == "String"
    regex.match(weak_mode_patterns[_], value.value)
}

check_key_size(value) {
    value.ir_type == "Integer"
    value.value < key_size_threshold
}

check_aes_key_size(value) {
    value.ir_type == "Integer"
    value.value < aes_key_threshold
}

check_iteration_count(value) {
    value.ir_type == "Integer"
    value.value < iteration_threshold
}

find_weak_crypto_strings(node) = result_node {
    walk(node, [path, n])
    n.ir_type == "String"
    check_weak_algorithm(n)
    result_node := n
} else {
    walk(node, [path, n])
    n.ir_type == "String"
    check_weak_protocol(n)
    result_node := n
} else {
    walk(node, [path, n])
    n.ir_type == "String"
    check_weak_mode(n)
    result_node := n
}

is_crypto_context(node) {
    node.ir_type == "Attribute"
    check_crypto_name(node.name)
} else {
    node.ir_type == "Variable"
    check_crypto_name(node.name)
} else {
    node.ir_type == "FunctionCall"
    check_crypto_name(node.name)
} else {
    node.ir_type == "Hash"
    some key
    key = node.value[_].key
    key.ir_type == "String"
    check_crypto_name(key.value)
}

check_weak_string(n) {
    check_weak_algorithm(n)
}

check_weak_string(n) {
    check_weak_protocol(n)
}

check_weak_string(n) {
    check_weak_mode(n)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    check_crypto_name(attr.name)
    weak_string := find_weak_crypto_strings(attr.value)
    is_weak := weak_string != null
    is_weak
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cryptographic configuration detected in attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    vars := glitch_lib.all_variables(node)
    var := vars[_]
    check_crypto_name(var.name)
    weak_string := find_weak_crypto_strings(var.value)
    is_weak := weak_string != null
    is_weak
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Weak cryptographic configuration detected in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "FunctionCall"
    check_crypto_name(n.name)
    arg := n.args[_]
    weak_string := find_weak_crypto_strings(arg)
    is_weak := weak_string != null
    is_weak
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of weak hashing algorithm in function call. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Hash"
    some key, value
    key = n.value[_].key
    value = n.value[_].value
    key.ir_type == "String"
    check_crypto_name(key.value)
    weak_string := find_weak_crypto_strings(value)
    is_weak := weak_string != null
    is_weak
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak cryptographic configuration detected in hash. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "Access"
    weak_string := find_weak_crypto_strings(n.right)
    is_weak := weak_string != null
    is_weak
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak cryptographic configuration detected in access expression. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "String"
    check_weak_string(n)
    count(path) > 0
    parent_path := array.slice(path, 0, count(path) - 1)
    parent_nodes := { p_n | walk(parent, [p_path, p_n]); p_path == parent_path }
    count(parent_nodes) == 1
    parent_node := parent_nodes[_]
    is_crypto_context(parent_node)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak cryptographic string detected in cryptographic context. (CWE-326)"
    }
}