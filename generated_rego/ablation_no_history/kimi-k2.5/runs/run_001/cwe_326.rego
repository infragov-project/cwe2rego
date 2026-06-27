package glitch

import data.glitch_lib

weak_algorithms_exact := {"des", "3des", "tripledes", "rc2", "rc4", "blowfish", "md5", "md4", "md2", "sha0", "sha1", "sha-0", "sha-1", "ripemd", "ripemd128", "ripemd160", "ecb"}

weak_algorithms_pattern := "^.*(des|3des|rc2|rc4|blowfish|md5|md4|md2|sha[-_]?0|sha[-_]?1|ripemd).*$"

weak_tls_pattern := "^.*(tls[-_]?v?1\\.?0|tls[-_]?v?1\\.?1|sslv?2|sslv?3|ssl[-_]?2|ssl[-_]?3).*$"

weak_ciphers_pattern := "^.*(export|anon|null|rc4[-_]?sha|des[-_]?cbc|cbc[-_]?sha).*$"

encryption_attr_names := {"encrypt", "encryption", "cipher", "algorithm", "hash", "digest", "protocol", "tls_version", "ssl_version", "policy", "cipher_suite"}

key_size_attr_names := {"key_size", "key_length", "key_bits", "keylen", "salt_size", "salt_length", "salt_len"}

is_weak_algorithm(val) {
    val.ir_type == "String"
    weak_algorithms_exact[lower(val.value)]
} else {
    val.ir_type == "String"
    regex.match(weak_algorithms_pattern, val.value)
} else {
    val.ir_type == "String"
    regex.match(weak_tls_pattern, lower(val.value))
} else {
    val.ir_type == "String"
    regex.match(weak_ciphers_pattern, lower(val.value))
}

is_small_key_size(val) {
    val.ir_type == "Integer"
    val.value > 0
    val.value < 128
} else {
    val.ir_type == "String"
    regex.match("^[0-9]+$", val.value)
    num := to_number(val.value)
    num > 0
    num < 128
}

is_encryption_attr(name) {
    encryption_attr_names[lower(name)]
} else {
    lower(name) == "type"
}

is_key_size_attr(name) {
    key_size_attr_names[lower(name)]
}

extract_hash_entries(node) := entries {
    node.ir_type == "Hash"
    entries := node.value
}

extract_hash_entries(node) := entries {
    not node.ir_type == "Hash"
    entries := []
}

check_nested_value_for_weak(val) {
    val.ir_type == "String"
    is_weak_algorithm(val)
} else {
    val.ir_type == "MethodCall"
    val.receiver.ir_type == "String"
    is_weak_algorithm(val.receiver)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_encryption_attr(attr.name)
    check_nested_value_for_weak(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm or protocol specified. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_key_size_attr(attr.name)
    is_small_key_size(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Key or salt size too small for secure encryption. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_encryption_attr(var.name)
    check_nested_value_for_weak(var.value)

    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in variable assignment. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_key_size_attr(var.name)
    is_small_key_size(var.value)

    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Small key size in variable assignment. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    is_encryption_attr(entry.key.value)
    check_nested_value_for_weak(entry.value)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic configuration in hash structure. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    is_key_size_attr(entry.key.value)
    is_small_key_size(entry.value)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Small key size in hash structure. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Array"
    arr_elem := node.value[_]
    some entry in extract_hash_entries(arr_elem)
    entry.key.ir_type == "String"
    is_encryption_attr(entry.key.value)
    check_nested_value_for_weak(entry.value)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic configuration in array entry. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Array"
    arr_elem := node.value[_]
    some entry in extract_hash_entries(arr_elem)
    entry.key.ir_type == "String"
    is_key_size_attr(entry.key.value)
    is_small_key_size(entry.value)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Small key size in array entry. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    func_lower := lower(node.name)
    weak_algorithms_exact[func_lower]

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic function called. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    regex.match(weak_algorithms_pattern, lower(node.name))
    not weak_algorithms_exact[lower(node.name)]

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic function called. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    au.name.ir_type == "String"
    is_weak_algorithm(au.name)

    result := {
        "type": "sec_weak_crypt",
        "element": au,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in resource name. (CWE-326)"
    }
}