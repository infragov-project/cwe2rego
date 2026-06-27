package glitch

import data.glitch_lib

weak_crypto_algorithms := {
    "des", "3des", "des3", "md4", "md5", "sha1", "sha-1",
    "rc4", "rc2", "rc5", "blowfish", "tea", "xtea",
    "ecdh", "dsa", "dh", "evp_des", "evp_des_ecb", "evp_des_cbc",
    "mcrypt_des", "rot13", "rot25", "xor"
}

crypto_attr_names := {
    "digest", "hash", "algorithm", "cipher", "encryption",
    "encryption_algorithm", "hash_algorithm", "digest_algorithm",
    "checksum_algorithm", "hmac_algorithm", "key_algorithm",
    "cipher_suite", "crypto", "cryptography", "signature_algorithm",
    "mac_algorithm", "kdf_algorithm", "pbkdf2_algorithm", "key_exchange",
    "ssl_protocol", "tls_version", "ssl_version"
}

crypto_keywords := {"encrypt", "decrypt", "hash", "digest", "cipher", "crypto", "hmac", "sign", "verify", "ssl", "tls"}

contains_pattern(str, substr) {
    regex.match(sprintf("(?i).*%s.*", [substr]), str)
}

is_weak_crypto(str) {
    lower_str := lower(str)
    alg := weak_crypto_algorithms[_]
    contains_pattern(lower_str, alg)
}

check_string_weak_crypto(value) {
    value.ir_type == "String"
    is_weak_crypto(value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr_name_lower := lower(attr.name)
    attr_name_lower == crypto_attr_names[_]

    find_weak_crypto_in_nested_value(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak cryptographic algorithms such as DES, MD5, SHA1, etc. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "function"

    func_name := node.name
    has_crypto_keyword(func_name)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    find_weak_crypto_in_nested_value(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak cryptographic algorithms such as DES, MD5, SHA1, etc. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "FunctionCall"

    func_name := attr.value.name
    has_crypto_keyword(func_name)

    args := attr.value.args
    some i
    arg := args[i]
    find_weak_crypto_in_nested_value(arg)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak cryptographic algorithms such as DES, MD5, SHA1, etc. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "MethodCall"

    func_name := attr.value.method
    has_crypto_keyword(func_name)

    args := attr.value.args
    some i
    arg := args[i]
    find_weak_crypto_in_nested_value(arg)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak cryptographic algorithms such as DES, MD5, SHA1, etc. (CWE-327)"
    }
}

has_crypto_keyword(func_name) {
    lower_func := lower(func_name)
    keyword := crypto_keywords[_]
    contains_pattern(lower_func, keyword)
}

find_weak_crypto_in_nested_value(value) {
    check_string_weak_crypto(value)
}

find_weak_crypto_in_nested_value(value) {
    value.ir_type == "Array"
    some i
    val := value.value[i]
    check_string_weak_crypto(val)
}

find_weak_crypto_in_nested_value(value) {
    value.ir_type == "Hash"
    some key
    val := value.value[key]
    check_string_weak_crypto(val)
}

find_weak_crypto_in_nested_value(value) {
    value.ir_type == "MethodCall"
    check_string_weak_crypto(value.receiver)
}

find_weak_crypto_in_nested_value(value) {
    value.ir_type == "VariableReference"
    is_weak_crypto(value.value)
}