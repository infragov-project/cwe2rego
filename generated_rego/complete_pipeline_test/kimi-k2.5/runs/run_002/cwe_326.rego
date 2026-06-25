package glitch

import data.glitch_lib

weak_patterns := {"des", "3des", "rc2", "rc4", "blowfish", "idea", "cast5", "seed", "rabbit", "md5", "sha1", "tls1.0", "tls_1_0", "tls1.1", "tls_1_1", "sslv2", "sslv3", "tlsv1", "null", "export", "_anon_", "allow_all", "des_cbc", "secp160", "secp192", "p-192", "p-224", "brainpoolp160", "group 1", "group 2", "modp-768", "modp-1024", "md5_crypt", "sha1_crypt", "md5crypt", "sha1crypt", "cbc_sha"}

weak_rsa := {512, 768, 1024}

encryption_key_patterns := {"cipher", "encrypt", "mode", "hash", "digest", "mac", "hmac", "algorithm", "key_bit", "rsa_bits", "key_length", "key_size", "curve", "ecdsa", "diffie", "dh_group", "kex", "ssl", "tls", "protocol", "auth_method"}

weak_func_names := {"md5", "sha1", "des", "rc4"}

is_encryption_key(str) {
    lower_str := lower(str)
    pattern := encryption_key_patterns[_]
    regex.match(sprintf(".*%s.*", [pattern]), lower_str)
}

contains_weak(str) {
    lower_str := lower(str)
    pattern := weak_patterns[_]
    regex.match(sprintf(".*%s.*", [pattern]), lower_str)
}

extract_string(node) = val {
    node.ir_type == "String"
    val := node.value
} else = val {
    node.ir_type == "VariableReference"
    val := node.value
} else = val {
    node.ir_type == "Integer"
    val := sprintf("%d", [node.value])
} else = val {
    val := ""
}

check_value_direct(node) {
    node.ir_type == "String"
    contains_weak(node.value)
}

check_value_direct(node) {
    node.ir_type == "Integer"
    weak_rsa[node.value]
}

check_value_direct(node) {
    node.ir_type == "VariableReference"
    contains_weak(node.value)
}

has_weak_content(node) {
    walk(node, [_, child])
    child.ir_type == "String"
    contains_weak(child.value)
}

is_func_with_weak_arg(node) {
    node.ir_type == "FunctionCall"
    func_lower := lower(node.name)
    func_lower == "filter|hash"
    arg := node.args[_]
    arg.ir_type == "String"
    contains_weak(arg.value)
}

is_access_with_weak_key(node) {
    node.ir_type == "Access"
    node.right.ir_type == "String"
    contains_weak(node.right.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_encryption_key(node.name)
    check_value_direct(node.value)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - The resource uses weak encryption algorithms, insufficient key lengths, or deprecated cryptographic protocols. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "Variable"
    is_encryption_key(node.name)
    check_value_direct(node.value)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - The resource uses weak encryption algorithms, insufficient key lengths, or deprecated cryptographic protocols. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    key_str := extract_string(entry.key)
    is_encryption_key(key_str)
    check_value_direct(entry.value)

    result := {
        "type": "sec_weak_crypt",
        "element": entry,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - The resource uses weak encryption algorithms, insufficient key lengths, or deprecated cryptographic protocols. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    is_func_with_weak_arg(node)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - The resource uses weak encryption algorithms, insufficient key lengths, or deprecated cryptographic protocols. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    func_lower := lower(node.name)
    weak_func_names[func_lower]

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - The resource uses weak encryption algorithms, insufficient key lengths, or deprecated cryptographic protocols. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "MethodCall"
    method_lower := lower(node.method)
    weak_func_names[method_lower]

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - The resource uses weak encryption algorithms, insufficient key lengths, or deprecated cryptographic protocols. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "Access"
    is_access_with_weak_key(node)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - The resource uses weak encryption algorithms, insufficient key lengths, or deprecated cryptographic protocols. (CWE-326)"
    }
}