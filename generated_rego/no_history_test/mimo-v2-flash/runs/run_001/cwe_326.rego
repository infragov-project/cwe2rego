package glitch

import data.glitch_lib

weak_algorithms := {"des", "3des", "rc4", "md5", "sha1", "aes-128", "tls 1.0", "tls 1.1", "sslv2", "sslv3", "md5_crypt", "TLS_RSA_WITH_AES_128_CBC_SHA"}

encryption_related_names := {"encrypt", "encryption", "cipher", "tls", "ssl", "key", "algorithm", "hash", "password", "private", "auth_method", "authentication", "auth", "cipher_suites"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    not node.value.ir_type == "Comment"
    glitch_lib.contains(node.name, encryption_related_names[_])
    value := node.value
    value.ir_type == "String"
    glitch_lib.contains(value.value, weak_algorithms[_])
    result := {
        "type": "sec_weak_crypt",
        "element": value,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak encryption algorithm or configuration detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    glitch_lib.contains(node.name, encryption_related_names[_])
    value := node.value
    value.ir_type == "String"
    glitch_lib.contains(value.value, weak_algorithms[_])
    result := {
        "type": "sec_weak_crypt",
        "element": value,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak encryption algorithm or configuration detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    glitch_lib.contains(node.name, weak_algorithms[_])
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak encryption algorithm or configuration detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    glitch_lib.contains(node.name, encryption_related_names[_])
    arg := node.args[_]
    arg.ir_type == "String"
    glitch_lib.contains(arg.value, weak_algorithms[_])
    result := {
        "type": "sec_weak_crypt",
        "element": arg,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak encryption algorithm or configuration detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    glitch_lib.contains(node.name, encryption_related_names[_])
    value := node.value
    value.ir_type == "Boolean"
    value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Encryption disabled. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    glitch_lib.contains(node.name, encryption_related_names[_])
    value := node.value
    value.ir_type == "Boolean"
    value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Encryption disabled. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    key := kv.key
    value := kv.value
    key.ir_type == "String"
    glitch_lib.contains(key.value, encryption_related_names[_])
    value.ir_type == "String"
    glitch_lib.contains(value.value, weak_algorithms[_])
    result := {
        "type": "sec_weak_crypt",
        "element": value,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak encryption algorithm or configuration detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Access"
    node.right.ir_type == "String"
    glitch_lib.contains(node.right.value, weak_algorithms[_])
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak encryption algorithm or configuration detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Array"
    item := node.value[_]
    item.ir_type == "Hash"
    kv := item.value[_]
    key := kv.key
    value := kv.value
    key.ir_type == "String"
    glitch_lib.contains(key.value, encryption_related_names[_])
    value.ir_type == "String"
    glitch_lib.contains(value.value, weak_algorithms[_])
    result := {
        "type": "sec_weak_crypt",
        "element": value,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak encryption algorithm or configuration detected. (CWE-326)"
    }
}