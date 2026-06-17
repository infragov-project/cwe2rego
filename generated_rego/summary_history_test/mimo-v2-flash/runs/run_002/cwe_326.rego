package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC4", "AES128", "AES_128", "SHA1", "SHA", "MD5", "ECB", "RC2", "Blowfish", "md5_crypt"}
outdated_protocols := {"TLS-1-0", "TLS-1-1", "SSLv2", "SSLv3"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    check_weak_algorithm(node.value)
    check_cryptographic_context(path, node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    node.value.ir_type == "String"
    check_weak_algorithm(node.value.value)
    check_cryptographic_context(path, node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption algorithm detected in variable (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "String"
    check_weak_algorithm(node.value.value)
    check_cryptographic_context(path, node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption algorithm detected in attribute (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    kv.value.ir_type == "String"
    check_weak_algorithm(kv.value.value)
    check_hash_context(path, node, kv)
    result := {
        "type": "sec_weak_crypt",
        "element": kv.value,
        "path": parent.path,
        "description": "Weak encryption algorithm detected in hash value (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Array"
    element := node.value[_]
    element.ir_type == "String"
    check_weak_algorithm(element.value)
    check_cryptographic_context(path, element)
    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Weak encryption algorithm detected in array element (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Integer"
    check_insufficient_key_size(node, path)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Insufficient key size detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    check_outdated_protocol(node.value)
    check_protocol_context(path, node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Outdated TLS protocol detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Boolean"
    node.value == false
    check_encryption_context(path, node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Encryption explicitly disabled (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    regex.match("(?i)\\bECB\\b", node.value)
    check_mode_context(path, node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Insecure ECB encryption mode detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    check_weak_algorithm(node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption algorithm detected in function call (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    check_weak_algorithm_in_args(node.args)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption algorithm detected in function call arguments (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Access"
    check_weak_algorithm_in_access(node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption algorithm detected in access expression (CWE-326)"
    }
}

check_weak_algorithm(value) {
    weak_algorithms[_] = algorithm
    regex.match(sprintf("(?i).*%s.*", [algorithm]), value)
}

check_weak_algorithm_in_args(args) {
    some i
    arg := args[i]
    arg.ir_type == "String"
    check_weak_algorithm(arg.value)
}

check_weak_algorithm_in_access(node) {
    node.right.ir_type == "String"
    check_weak_algorithm(node.right.value)
}

check_insufficient_key_size(node, path) {
    node.value < 256
    check_key_size_context(path, node)
}

check_insufficient_key_size(node, path) {
    node.value < 2048
    check_rsa_key_context(path, node)
}

check_key_size_context(path, node) {
    check_context_keywords(path, {"key", "size", "length", "bits"})
}

check_rsa_key_context(path, node) {
    check_context_keywords(path, {"rsa", "bits"})
}

check_outdated_protocol(value) {
    outdated_protocols[_] = protocol
    regex.match(sprintf("(?i).*%s.*", [protocol]), value)
}

check_protocol_context(path, node) {
    check_context_keywords(path, {"protocol", "ssl", "tls", "cipher"})
}

check_encryption_context(path, node) {
    check_context_keywords(path, {"encryption", "encrypt"})
}

check_mode_context(path, node) {
    check_context_keywords(path, {"mode"})
}

check_cryptographic_context(path, node) {
    check_context_keywords(path, {"algorithm", "cipher", "encrypt", "key", "protocol", "ssl", "tls", "mode", "crypto", "cryptographic", "password", "hash", "auth", "authentication", "method"})
}

check_hash_context(path, node, kv) {
    kv.key.ir_type == "String"
    check_context_keywords(path, {"algorithm", "cipher", "encrypt", "key", "protocol", "ssl", "tls", "mode", "crypto", "cryptographic", "password", "hash", "auth", "authentication", "method"})
}

check_hash_context(path, node, kv) {
    kv.key.ir_type == "String"
    regex.match("(?i)(algorithm|cipher|encrypt|key|protocol|ssl|tls|mode|crypto|cryptographic|password|hash|auth|authentication|method)", kv.key.value)
}

check_context_keywords(path, keywords) {
    some i
    node_in_path := path[i]
    node_in_path.ir_type == "Attribute"
    some kw_idx
    keyword := keywords[kw_idx]
    regex.match(sprintf("(?i).*%s.*", [keyword]), node_in_path.name)
}

check_context_keywords(path, keywords) {
    some i
    node_in_path := path[i]
    node_in_path.ir_type == "Variable"
    some kw_idx
    keyword := keywords[kw_idx]
    regex.match(sprintf("(?i).*%s.*", [keyword]), node_in_path.name)
}

check_context_keywords(path, keywords) {
    some i
    node_in_path := path[i]
    node_in_path.ir_type == "String"
    some kw_idx
    keyword := keywords[kw_idx]
    regex.match(sprintf("(?i).*%s.*", [keyword]), node_in_path.value)
}

check_context_keywords(path, keywords) {
    some i
    node_in_path := path[i]
    node_in_path.ir_type == "Hash"
    some kv_idx
    kv := node_in_path.value[kv_idx]
    kv.key.ir_type == "String"
    some kw_idx
    keyword := keywords[kw_idx]
    regex.match(sprintf("(?i).*%s.*", [keyword]), kv.key.value)
}

check_context_keywords(path, keywords) {
    some i
    node_in_path := path[i]
    node_in_path.ir_type == "AtomicUnit"
    some kw_idx
    keyword := keywords[kw_idx]
    regex.match(sprintf("(?i).*%s.*", [keyword]), node_in_path.type)
}

check_context_keywords(path, keywords) {
    some i
    node_in_path := path[i]
    node_in_path.ir_type == "UnitBlock"
    some kw_idx
    keyword := keywords[kw_idx]
    regex.match(sprintf("(?i).*%s.*", [keyword]), node_in_path.name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    contains_weak_algorithm_in_list(node.value)
    check_cryptographic_context(path, node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption algorithm in list detected (CWE-326)"
    }
}

contains_weak_algorithm_in_list(value) {
    regex.match("(?i).*\\[.*\\].*", value)
    algorithm_list := regex.split("(?i)[,\\[\\]\\s]+", value)
    some algorithm
    algorithm := algorithm_list[_]
    check_weak_algorithm(algorithm)
}

contains_weak_algorithm_in_list(value) {
    not regex.match("(?i).*\\[.*\\].*", value)
    algorithm_list := regex.split("(?i)[,\\s]+", value)
    some alg
    alg := algorithm_list[_]
    check_weak_algorithm(alg)
}