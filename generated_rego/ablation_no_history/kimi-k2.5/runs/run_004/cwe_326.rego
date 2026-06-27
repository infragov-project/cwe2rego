package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC2", "RC4", "MD5", "SHA1", "SHA-1", "MD5CRYPT", "MD5_CRYPT", "md5_crypt", "sha1", "md5", "SHA_1", "MD5_CRYPT"}

weak_tls_versions := {"SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "TLS_1_0", "TLS_1_1", "TLSv1.0", "TLSv1.1"}

weak_cipher_suites := {"TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "AES_128_CBC", "AES128-CBC", "DES-CBC3-SHA", "RC4-SHA", "RC4-MD5"}

crypto_attr_names := {"algorithm", "cipher", "encrypt", "encryption", "hash", "digest", "checksum", "crypto", "tls_version", "ssl_version", "protocol", "cipher_suite", "cipher_suites", "key_spec", "key_usage", "customer_master_key_spec", "sse_algorithm", "storage_encrypted", "encrypted", "password", "password_md5", "auth_method", "key_derivation"}

contains_weak_algo(str) {
    algo := weak_algorithms[_]
    regex.match(sprintf("(?i)%s", [algo]), str)
}

contains_weak_tls(str) {
    tls := weak_tls_versions[_]
    regex.match(sprintf("(?i)%s", [tls]), str)
}

contains_weak_cipher_suite(str) {
    suite := weak_cipher_suites[_]
    regex.match(sprintf("(?i)%s", [suite]), str)
}

is_crypto_related_name(name) {
    keyword := crypto_attr_names[_]
    regex.match(sprintf("(?i)%s", [keyword]), name)
}

is_weak_crypto_value(val) {
    val.ir_type == "String"
    contains_weak_algo(val.value)
} else {
    val.ir_type == "String"
    contains_weak_tls(val.value)
} else {
    val.ir_type == "String"
    contains_weak_cipher_suite(val.value)
}

is_weak_crypto_in_function_call(node) {
    node.ir_type == "FunctionCall"
    func_name := lower(node.name)
    contains_weak_algo(func_name)
} else {
    node.ir_type == "FunctionCall"
    arg := node.args[_]
    is_weak_crypto_value(arg)
}

has_weak_crypto_in_tree(val) {
    walk(val, [_, node])
    is_weak_crypto_value(node)
} else {
    walk(val, [_, node])
    is_weak_crypto_in_function_call(node)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "FunctionCall"
    is_weak_crypto_in_function_call(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of weak or deprecated cryptographic algorithm or protocol. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    is_crypto_related_name(attr.name)
    has_weak_crypto_in_tree(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak or deprecated cryptographic algorithm or protocol. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_crypto_related_name(var.name)
    has_weak_crypto_in_tree(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of weak or deprecated cryptographic algorithm or protocol. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    some key
    entry := node.value[key]
    key.ir_type == "String"
    is_crypto_related_name(key.value)
    has_weak_crypto_in_tree(entry)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak or deprecated cryptographic algorithm or protocol. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Array"
    item := node.value[_]
    item.ir_type == "Hash"
    some key
    entry := item.value[key]
    key.ir_type == "String"
    is_crypto_related_name(key.value)
    has_weak_crypto_in_tree(entry)
    result := {
        "type": "sec_weak_crypt",
        "element": item,
        "path": parent.path,
        "description": "Use of weak or deprecated cryptographic algorithm or protocol. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    arr_item := attr.value.value[_]
    arr_item.ir_type == "Hash"
    some key
    entry := arr_item.value[key]
    key.ir_type == "String"
    is_crypto_related_name(key.value)
    has_weak_crypto_in_tree(entry)
    result := {
        "type": "sec_weak_crypt",
        "element": arr_item,
        "path": parent.path,
        "description": "Use of weak or deprecated cryptographic algorithm or protocol. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    some key
    entry := attr.value.value[key]
    key.ir_type == "String"
    is_crypto_related_name(key.value)
    has_weak_crypto_in_tree(entry)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak or deprecated cryptographic algorithm or protocol. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "AtomicUnit"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_weak_crypto_value(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak or deprecated cryptographic algorithm or protocol. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    is_weak_crypto_value(node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak or deprecated cryptographic algorithm or protocol. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    is_weak_crypto_in_function_call(node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak or deprecated cryptographic algorithm or protocol. (CWE-326)"
    }
}