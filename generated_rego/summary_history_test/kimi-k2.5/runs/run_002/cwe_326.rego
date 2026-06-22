package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "TDES", "RC2", "RC4", "BLOWFISH", "MD5", "SHA1", "SHA-1", "RSA-1024", "DSA", "ECB", "CBC", "MD5_CRYPT"}

weak_hash_keywords := {"MD5", "SHA1", "SHA-1"}

is_weak_algorithm(val) {
    upper_val := upper(val)
    alg := weak_algorithms[_]
    upper_val == alg
} else {
    upper_val := upper(val)
    alg := weak_algorithms[_]
    contains(upper_val, alg)
}

is_weak_hash_func(val) {
    upper_val := upper(val)
    kw := weak_hash_keywords[_]
    contains(upper_val, kw)
}

has_weak_algorithm_in_string(str) {
    is_weak_algorithm(str)
} else {
    is_weak_hash_func(str)
}

is_encryption_field(name) {
    contains(lower(name), "encrypt")
}

is_hash_field(name) {
    contains(lower(name), "hash")
}

is_cipher_field(name) {
    lower_name := lower(name)
    contains(lower_name, "cipher")
    not contains(lower_name, "include")
}

is_algorithm_field(name) {
    lower_name := lower(name)
    contains(lower_name, "algorithm")
    not contains(lower_name, "include")
}

is_auth_method_field(name) {
    lower(name) == "auth_method"
}

is_password_field(name) {
    contains(lower(name), "password")
}

is_weak_function_name(name) {
    fname := lower(name)
    fname == "md5"
} else {
    fname := lower(name)
    fname == "sha1"
} else {
    fname := lower(name)
    contains(fname, "md5")
} else {
    fname := lower(name)
    contains(fname, "sha1")
}

is_hash_function_name(name) {
    lower_name := lower(name)
    contains(lower_name, "hash")
}

check_access_for_weak_hash(access_node) {
    access_node.ir_type == "Access"
    access_node.right.ir_type == "String"
    contains(lower(access_node.right.value), "md5")
} else {
    access_node.ir_type == "Access"
    access_node.right.ir_type == "String"
    contains(lower(access_node.right.value), "sha1")
}

check_function_call_arg_for_weak_hash(node) {
    node.ir_type == "FunctionCall"
    is_hash_function_name(node.name)
    arg := node.args[_]
    arg.ir_type == "String"
    has_weak_algorithm_in_string(arg.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, node] := walk(parent)
    node.ir_type == "FunctionCall"
    is_weak_function_name(node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic function call detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, node] := walk(parent)
    node.ir_type == "FunctionCall"
    check_function_call_arg_for_weak_hash(node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak hash algorithm in function call detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, node] := walk(parent)
    node.ir_type == "Attribute"
    is_password_field(node.name)
    node.value.ir_type == "Access"
    check_access_for_weak_hash(node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak hash algorithm used for password. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, node] := walk(parent)
    node.ir_type == "Variable"
    is_password_field(node.name)
    node.value.ir_type == "FunctionCall"
    is_weak_function_name(node.value.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak hash algorithm used for password variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, node] := walk(parent)
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    is_encryption_field(entry.key.value)
    entry.value.ir_type == "String"
    has_weak_algorithm_in_string(entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak encryption algorithm in hash entry. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, node] := walk(parent)
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    is_hash_field(entry.key.value)
    entry.value.ir_type == "String"
    has_weak_algorithm_in_string(entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak hash algorithm in hash entry. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, node] := walk(parent)
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    is_cipher_field(entry.key.value)
    entry.value.ir_type == "String"
    has_weak_algorithm_in_string(entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher in hash entry. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, node] := walk(parent)
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    is_algorithm_field(entry.key.value)
    entry.value.ir_type == "String"
    has_weak_algorithm_in_string(entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak algorithm in hash entry. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, node] := walk(parent)
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    is_auth_method_field(entry.key.value)
    entry.value.ir_type == "String"
    has_weak_algorithm_in_string(entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak authentication method in hash entry. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    [_, attr] := walk(node)
    attr.ir_type == "Attribute"
    is_encryption_field(attr.name)
    attr.value.ir_type == "String"
    has_weak_algorithm_in_string(attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak encryption algorithm in attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    [_, attr] := walk(node)
    attr.ir_type == "Attribute"
    is_cipher_field(attr.name)
    attr.value.ir_type == "String"
    has_weak_algorithm_in_string(attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher in attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    [_, attr] := walk(node)
    attr.ir_type == "Attribute"
    is_hash_field(attr.name)
    attr.value.ir_type == "String"
    has_weak_algorithm_in_string(attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak hash algorithm in attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    [_, attr] := walk(node)
    attr.ir_type == "Attribute"
    is_algorithm_field(attr.name)
    attr.value.ir_type == "String"
    has_weak_algorithm_in_string(attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak algorithm in attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    [_, attr] := walk(node)
    attr.ir_type == "Attribute"
    is_auth_method_field(attr.name)
    attr.value.ir_type == "String"
    has_weak_algorithm_in_string(attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak authentication method in attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, node] := walk(parent)
    node.ir_type == "Variable"
    is_cipher_field(node.name)
    node.value.ir_type == "String"
    has_weak_algorithm_in_string(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, node] := walk(parent)
    node.ir_type == "Variable"
    is_hash_field(node.name)
    node.value.ir_type == "String"
    has_weak_algorithm_in_string(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak hash algorithm in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, node] := walk(parent)
    node.ir_type == "Variable"
    is_algorithm_field(node.name)
    node.value.ir_type == "String"
    has_weak_algorithm_in_string(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak algorithm in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, node] := walk(parent)
    node.ir_type == "Variable"
    is_encryption_field(node.name)
    node.value.ir_type == "String"
    has_weak_algorithm_in_string(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak encryption algorithm in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    [_, node] := walk(parent)
    node.ir_type == "Variable"
    is_auth_method_field(node.name)
    node.value.ir_type == "String"
    has_weak_algorithm_in_string(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak authentication method in variable. (CWE-326)"
    }
}