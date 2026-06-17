package glitch

import data.glitch_lib

find_nodes(node) = nodes {
    allowed_types := {"Attribute", "Variable", "String", "Integer", "Boolean", "FunctionCall", "Access"}
    nodes := {{"node": n, "path": p} | [p, n] := walk(node); allowed_types[n.ir_type]}
}

check_weak_algorithm(node) {
    node.ir_type == "String"
    regex.match("(?i)\\b(des|3des|tripledes|rc4|arc4|rsa1024|aes-128|blowfish|sha1|md5)\\b", node.value)
} else {
    node.ir_type == "FunctionCall"
    check_weak_algorithm_in_function(node)
} else {
    node.ir_type == "Access"
    regex.match("(?i)\\b(des|3des|tripledes|rc4|arc4|rsa1024|aes-128|blowfish|sha1|md5)\\b", node.code)
}

check_weak_algorithm_in_function(node) {
    regex.match("(?i)\\b(des|3des|tripledes|rc4|arc4|rsa1024|aes-128|blowfish|sha1|md5)\\b", node.name)
} else {
    check_weak_algorithm_in_args(node.args)
}

check_weak_algorithm_in_args(args) {
    arg := args[_]
    arg.ir_type == "String"
    regex.match("(?i)\\b(des|3des|tripledes|rc4|arc4|rsa1024|aes-128|blowfish|sha1|md5)\\b", arg.value)
}

check_key_length(node, min_bits) {
    node.ir_type == "Integer"
    node.value < min_bits
}

check_outdated_protocol(node) {
    node.ir_type == "String"
    regex.match("(?i)^(ssl-v2|ssl-v3|tls-1\\.0|tls-1\\.1|tls-1-0|tls-1-1|http|ssh-v1)$", node.value)
}

check_weak_cipher(node) {
    node.ir_type == "String"
    cipher_value := node.value
    cleaned := regex.replace("\\[|\\]", cipher_value, "")
    ciphers := regex.split("\\s*,\\s*", cleaned)
    cipher := ciphers[_]
    regex.match("(?i)(rc4|des|3des|md5|sha1|null|export|anonymous|cbc)", cipher)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node_objs := find_nodes(parent)
    node_obj := node_objs[_]
    node := node_obj.node
    path := node_obj.path
    node.ir_type == "String"
    check_weak_algorithm(node)
    path_str := concat("/", path)
    not regex.match("(?i)shell|command", path_str)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak encryption algorithm - Avoid using weak encryption algorithms such as DES, RC4, etc. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node_objs := find_nodes(parent)
    node_obj := node_objs[_]
    node := node_obj.node
    node.ir_type == "FunctionCall"
    check_weak_algorithm_in_function(node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak encryption algorithm in function call - Avoid using weak encryption algorithms such as DES, RC4, etc. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node_objs := find_nodes(parent)
    node_obj := node_objs[_]
    node := node_obj.node
    path := node_obj.path
    node.ir_type == "Integer"
    path_str := concat("/", path)
    regex.match("(?i)(key_size|key_length|bits|strength|key_spec|key_length_bits)", path_str)
    check_key_length(node, 128)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Insufficient key length - Key length is too short (less than 128 bits). (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node_objs := find_nodes(parent)
    node_obj := node_objs[_]
    node := node_obj.node
    path := node_obj.path
    node.ir_type == "Integer"
    path_str := concat("/", path)
    regex.match("(?i)(rsa|dsa)", path_str)
    check_key_length(node, 2048)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Insufficient key length for RSA/DSA - Key length is less than 2048 bits. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node_objs := find_nodes(parent)
    node_obj := node_objs[_]
    node := node_obj.node
    path := node_obj.path
    node.ir_type == "Integer"
    path_str := concat("/", path)
    regex.match("(?i)ecdsa", path_str)
    check_key_length(node, 256)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Insufficient key length for ECDSA - Key length is less than 256 bits. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node_objs := find_nodes(parent)
    node_obj := node_objs[_]
    node := node_obj.node
    path := node_obj.path
    node.ir_type == "String"
    path_str := concat("/", path)
    regex.match("(?i)(protocol|tls_version|ssl_policy|tls_policy|encryption_protocol)", path_str)
    check_outdated_protocol(node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of outdated protocol - Avoid using deprecated protocols like SSLv2, SSLv3, TLS 1.0, TLS 1.1, etc. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node_objs := find_nodes(parent)
    node_obj := node_objs[_]
    node := node_obj.node
    path := node_obj.path
    node.ir_type == "String"
    path_str := concat("/", path)
    regex.match("(?i)cipher", path_str)
    check_weak_cipher(node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Insecure cipher suite - Cipher suite contains weak algorithms (e.g., RC4, DES, 3DES, MD5, SHA1, etc.). (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node_objs := find_nodes(parent)
    node_obj := node_objs[_]
    node := node_obj.node
    path := node_obj.path
    node.ir_type == "String"
    path_str := concat("/", path)
    regex.match("(?i)(secret|key|password|iv|salt|nonce|token|passphrase)", path_str)
    node.value != ""
    not regex.match("(?i)(example|test|placeholder)", node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Hardcoded cryptographic value - Avoid hardcoding secrets, keys, passwords, etc. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node_objs := find_nodes(parent)
    node_obj := node_objs[_]
    node := node_obj.node
    path := node_obj.path
    node.ir_type == "Access"
    path_str := concat("/", path)
    regex.match("(?i)(secret|key|password|iv|salt|nonce|token|passphrase)", path_str)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Hardcoded cryptographic value in access expression - Avoid hardcoding secrets, keys, passwords, etc. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node_objs := find_nodes(parent)
    node_obj := node_objs[_]
    node := node_obj.node
    path := node_obj.path
    node.ir_type == "Boolean"
    path_str := concat("/", path)
    regex.match("(?i)reuse_iv", path_str)
    node.value == true
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Reused IVs - Initialization vectors (IVs) should not be reused. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node_objs := find_nodes(parent)
    node_obj := node_objs[_]
    node := node_obj.node
    path := node_obj.path
    node.ir_type == "String"
    path_str := concat("/", path)
    regex.match("(?i)salt", path_str)
    node.value != ""
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Fixed salt - Salts should be randomly generated and not hardcoded. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node_objs := find_nodes(parent)
    node_obj := node_objs[_]
    node := node_obj.node
    path := node_obj.path
    node.ir_type == "Boolean"
    path_str := concat("/", path)
    regex.match("(?i)(encryption_enabled|enable_encryption|encryption)", path_str)
    node.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Encryption disabled - Encryption should be enabled for sensitive data. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node_objs := find_nodes(parent)
    node_obj := node_objs[_]
    node := node_obj.node
    path := node_obj.path
    node.ir_type == "Boolean"
    path_str := concat("/", path)
    regex.match("(?i)(rotation_enabled|key_rotation|rotate_keys)", path_str)
    node.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Key rotation disabled - Keys should be rotated regularly (at least every 90 days). (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    node_objs := find_nodes(parent)
    node_obj := node_objs[_]
    node := node_obj.node
    path := node_obj.path
    node.ir_type == "Integer"
    path_str := concat("/", path)
    regex.match("(?i)rotation_period", path_str)
    node.value > 90
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Excessive rotation period - Rotation period should be at most 90 days. (CWE-326)"
    }
}