package glitch

import data.glitch_lib
import future.keywords.in

weak_crypto_set := {"md5", "md4", "md2", "sha", "sha0", "sha-0", "sha1", "sha-1", "des", "3des", "rc4", "dss", "dsa", "ecdsa-sha1", "ripemd", "ripemd128", "ripemd160", "whirlpool", "haval", "panama", "snerfu", "gost", "md6", "md5crypt", "md5_sha1", "md5_crypt", "sha-1-hmac", "sha1-hmac"}

weak_crypto_exact := {"md5", "md4", "md2", "sha1", "sha-1", "des", "3des", "rc4", "md5crypt", "md5_crypt", "md5_sha1"}

is_weak_crypto_exact(value) {
    lower_val := lower(value)
    weak_crypto_exact[lower_val]
}

has_weak_algo_prefix(value) {
    lower_val := lower(value)
    startswith(lower_val, "md5")
}

has_weak_algo_prefix(value) {
    lower_val := lower(value)
    startswith(lower_val, "sha1")
}

has_weak_algo_prefix(value) {
    lower_val := lower(value)
    startswith(lower_val, "sha-1")
}

has_weak_algo_prefix(value) {
    lower_val := lower(value)
    startswith(lower_val, "des")
}

has_weak_algo_prefix(value) {
    lower_val := lower(value)
    startswith(lower_val, "3des")
}

has_weak_algo_prefix(value) {
    lower_val := lower(value)
    startswith(lower_val, "rc4")
}

has_weak_algo_suffix(value) {
    lower_val := lower(value)
    endswith(lower_val, "md5")
}

has_weak_algo_suffix(value) {
    lower_val := lower(value)
    endswith(lower_val, "sha1")
}

has_weak_algo_suffix(value) {
    lower_val := lower(value)
    endswith(lower_val, "sha-1")
}

has_weak_algo_suffix(value) {
    lower_val := lower(value)
    endswith(lower_val, "des")
}

has_weak_algo_suffix(value) {
    lower_val := lower(value)
    endswith(lower_val, "3des")
}

has_weak_algo_suffix(value) {
    lower_val := lower(value)
    endswith(lower_val, "rc4")
}

contains_weak_algo_anywhere(value) {
    lower_val := lower(value)
    contains(lower_val, "md5")
}

contains_weak_algo_anywhere(value) {
    lower_val := lower(value)
    contains(lower_val, "sha1")
}

contains_weak_algo_anywhere(value) {
    lower_val := lower(value)
    contains(lower_val, "sha-1")
}

contains_weak_algo_anywhere(value) {
    lower_val := lower(value)
    contains(lower_val, "des")
}

contains_weak_algo_anywhere(value) {
    lower_val := lower(value)
    contains(lower_val, "rc4")
}

check_crypto_value(s) {
    is_weak_crypto_exact(s)
} else {
    has_weak_algo_prefix(s)
} else {
    has_weak_algo_suffix(s)
} else {
    contains_weak_algo_anywhere(s)
}

crypto_context_keywords := {"encrypt", "cipher", "hash", "digest", "auth", "checksum", "crypto", "password", "method", "suite", "ssl", "tls", "algorithm", "sign"}

is_crypto_context(name) {
    lower_name := lower(name)
    some kw in crypto_context_keywords
    contains(lower_name, kw)
}

is_likely_crypto_config_value(s) {
    lower(s) == "true"
} else {
    lower(s) == "false"
} else {
    lower(s) == "yes"
} else {
    lower(s) == "no"
} else {
    regex.match(`^\d+$`, s)
}

get_string_value(node) = s {
    node.ir_type == "String"
    s := node.value
} else = s {
    node.ir_type == "VariableReference"
    s := node.value
}

get_any_string(node) = s {
    node.ir_type == "String"
    s := node.value
}

find_weak_crypto_in_args(args) = val {
    some arg in args
    arg.ir_type == "String"
    val := arg.value
    check_crypto_value(val)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some [_, node] in walk(parent)
    
    node.ir_type == "Attribute"
    attr_name := node.name
    
    is_crypto_context(attr_name)
    
    some [_, val_node] in walk(node.value)
    
    val_node.ir_type == "String"
    val := val_node.value
    
    check_crypto_value(val)
    
    not is_likely_crypto_config_value(val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": val_node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, broken, or deprecated cryptographic algorithms such as DES, MD5, SHA-1, or RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some [_, node] in walk(parent)
    
    node.ir_type == "Attribute"
    attr_name := node.name
    
    not is_crypto_context(attr_name)
    
    some [_, val_node] in walk(node.value)
    
    val_node.ir_type == "String"
    val := val_node.value
    
    check_crypto_value(val)
    
    not is_likely_crypto_config_value(val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": val_node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, broken, or deprecated cryptographic algorithms such as DES, MD5, SHA-1, or RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some [_, node] in walk(parent)
    
    node.ir_type == "Variable"
    var_name := node.name
    
    is_crypto_context(var_name)
    
    val_node := node.value
    val_type := val_node.ir_type
    val_type == "String"
    val := val_node.value
    
    check_crypto_value(val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": val_node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, broken, or deprecated cryptographic algorithms such as DES, MD5, SHA-1, or RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some [_, node] in walk(parent)
    
    node.ir_type == "Hash"
    
    some entry in node.value
    
    entry.key.ir_type == "String"
    key_name := entry.key.value
    
    is_crypto_context(key_name)
    
    entry.value.ir_type == "String"
    val := entry.value.value
    
    check_crypto_value(val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, broken, or deprecated cryptographic algorithms such as DES, MD5, SHA-1, or RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some [_, node] in walk(parent)
    
    node.ir_type == "FunctionCall"
    
    func_name := lower(node.name)
    
    contains(func_name, "hash")
    
    val := find_weak_crypto_in_args(node.args)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, broken, or deprecated cryptographic algorithms such as DES, MD5, SHA-1, or RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some [_, node] in walk(parent)
    
    node.ir_type == "FunctionCall"
    
    func_name := lower(node.name)
    weak_crypto_set[func_name]
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, broken, or deprecated cryptographic algorithms such as DES, MD5, SHA-1, or RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some [_, node] in walk(parent)
    
    node.ir_type == "Access"
    
    node.right.ir_type == "String"
    right_val := node.right.value
    
    check_crypto_value(right_val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node.right,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, broken, or deprecated cryptographic algorithms such as DES, MD5, SHA-1, or RC4. (CWE-327)"
    }
}