package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "TripleDES", "MD4", "MD5", "MD2", "SHA0", "SHA1", "SHA-1", "SHA_1", "RC2", "RC4", "Blowfish", "DSA", "TEA", "XTEA", "md5_crypt", "sha1_crypt", "des_crypt", "blowfish_crypt"}

weak_ciphers := {"ECB", "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLS 1.0", "TLS 1.1", "CBC_SHA", "_CBC_", "PKCS1v15", "CBC"}

weak_modes := {"CBC", "ECB"}

weak_tls_versions := {"TLSv1.0", "TLSv1.1", "TLS 1.0", "TLS 1.1", "SSLv2", "SSLv3", "ssl2", "ssl3", "tls1.0", "tls1.1"}

weak_hash_funcs := {"md5", "sha1", "sha-1", "sha_1", "md5_crypt"}

weak_func_names := {"md5", "sha1", "sha-1", "sha_1", "md5sum", "sha1sum", "crypt", "des", "blowfish"}

crypto_attr_names := {"encryption", "encrypt", "cipher", "algorithm", "crypto", "hash", "digest", "checksum", "ssl_policy", "tls_policy", "tls_version", "signature_algorithm", "key_exchange", "kms_key_id", "master_key", "encryption_key", "password_hash", "secret_hash", "auth_method", "protocol", "cipher_suites", "key_length", "key_size", "rsa_key_size", "ciphers", "ssl", "tls", "mode"}

check_weak_string(str) {
    some alg
    weak_algorithms[alg]
    regex.match(sprintf("(?i).*%s.*", [alg]), str)
}

check_weak_string(str) {
    some cipher
    weak_ciphers[cipher]
    regex.match(sprintf("(?i).*%s.*", [cipher]), str)
}

check_weak_string(str) {
    some hash_fn
    weak_hash_funcs[hash_fn]
    regex.match(sprintf("(?i).*%s.*", [hash_fn]), str)
}

check_weak_tls(str) {
    some ver
    weak_tls_versions[ver]
    regex.match(sprintf("(?i).*%s.*", [ver]), str)
}

is_crypto_context(name) {
    some attr
    crypto_attr_names[attr]
    regex.match(sprintf("(?i).*[_\\-\\.]?%s[_\\-\\.]?.*", [attr]), name)
}

is_weak_func_name(name) {
    some fn
    weak_func_names[fn]
    regex.match(sprintf("(?i)^%s$", [fn]), name)
}

is_weak_func_name(name) {
    some fn
    weak_func_names[fn]
    regex.match(sprintf("(?i).*%s.*", [fn]), name)
}

has_weak_string_in_value(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    check_weak_string(n.value)
}

has_weak_tls_in_value(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    check_weak_tls(n.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := {n |
        walk(parent, [_, n])
        n.ir_type == "Attribute"
    }
    attr := attrs[_]
    is_crypto_context(attr.name)
    has_weak_string_in_value(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak algorithm detected in cryptography-related attribute. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := {n |
        walk(parent, [_, n])
        n.ir_type == "Variable"
    }
    var := vars[_]
    is_crypto_context(var.name)
    has_weak_string_in_value(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak algorithm detected in cryptography-related variable. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := {n |
        walk(parent, [_, n])
        n.ir_type == "Attribute"
    }
    attr := attrs[_]
    regex.match("(?i)^(encrypt|encryption|algorithm|cipher|hash|digest)$", attr.name)
    attr.value.ir_type == "String"
    check_weak_string(attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak cryptographic algorithm specified. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := {n |
        walk(parent, [_, n])
        n.ir_type == "Variable"
    }
    var := vars[_]
    regex.match("(?i)^(encrypt|encryption|algorithm|cipher|hash|digest)$", var.name)
    var.value.ir_type == "String"
    check_weak_string(var.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak cryptographic algorithm in variable. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := {n |
        walk(parent, [_, n])
        n.ir_type == "Attribute"
    }
    attr := attrs[_]
    regex.match("(?i)tls_version|ssl_version|protocol", attr.name)
    has_weak_tls_in_value(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak TLS/SSL version detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := {n |
        walk(parent, [_, n])
        n.ir_type == "Attribute"
    }
    attr := attrs[_]
    regex.match("(?i)password|secret", attr.name)
    walk(attr.value, [_, n])
    n.ir_type == "String"
    regex.match("(?i).*md5.*|.*sha1.*|.*des.*", n.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak algorithm in password/secret configuration. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := {n |
        walk(parent, [_, n])
        n.ir_type == "Variable"
    }
    var := vars[_]
    var.value.ir_type == "FunctionCall"
    is_weak_func_name(var.value.name)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak cryptographic function call detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := {n |
        walk(parent, [_, n])
        n.ir_type == "Attribute"
    }
    attr := attrs[_]
    attr.value.ir_type == "FunctionCall"
    is_weak_func_name(attr.value.name)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak cryptographic function call in attribute. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nodes := {n |
        walk(parent, [_, n])
        n.ir_type == "Attribute"
        n.name == "key_length"
    }
    node := nodes[_]
    node.value.ir_type == "Integer"
    node.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Cryptographic key with insufficient length (< 2048 bits). (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nodes := {n |
        walk(parent, [_, n])
        n.ir_type == "Attribute"
        n.name == "key_size"
    }
    node := nodes[_]
    node.value.ir_type == "Integer"
    node.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Cryptographic key with insufficient length (< 2048 bits). (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nodes := {n |
        walk(parent, [_, n])
        n.ir_type == "Attribute"
        n.name == "rsa_key_size"
    }
    node := nodes[_]
    node.value.ir_type == "Integer"
    node.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Cryptographic key with insufficient length (< 2048 bits). (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := {n |
        walk(parent, [_, n])
        n.ir_type == "Variable"
    }
    var := vars[_]
    regex.match("(?i)^(key_length|key_size|rsa_key_size)$", var.name)
    var.value.ir_type == "Integer"
    var.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Cryptographic key with insufficient length (< 2048 bits). (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    hashes := {n |
        walk(parent, [_, n])
        n.ir_type == "Hash"
    }
    node := hashes[_]
    some kvi
    kv := node.value[kvi]
    kv.key.ir_type == "String"
    is_crypto_context(kv.key.value)
    kv.value.ir_type == "String"
    check_weak_string(kv.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak algorithm detected in hash structure. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    hashes := {n |
        walk(parent, [_, n])
        n.ir_type == "Hash"
    }
    node := hashes[_]
    some kvi
    kv := node.value[kvi]
    kv.key.ir_type == "String"
    regex.match("(?i)^(encrypt|encryption|algorithm|cipher|hash|mode)$", kv.key.value)
    kv.value.ir_type == "String"
    check_weak_string(kv.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak algorithm in hash key-value. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    hashes := {n |
        walk(parent, [_, n])
        n.ir_type == "Hash"
    }
    node := hashes[_]
    some kvi
    kv := node.value[kvi]
    kv.key.ir_type == "String"
    kv.key.value == "name"
    kv.value.ir_type == "String"
    regex.match("(?i).*password.*|.*secret.*", kv.value.value)
    some okvi
    other_kv := node.value[okvi]
    other_kv != kv
    other_kv.key.ir_type == "String"
    regex.match("(?i)^(encrypt|hash|algorithm)$", other_kv.key.value)
    other_kv.value.ir_type == "String"
    check_weak_string(other_kv.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": other_kv,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak algorithm used for password/secret encryption. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    arrays := {n |
        walk(parent, [_, n])
        n.ir_type == "Array"
    }
    node := arrays[_]
    some elti
    elt := node.value[elti]
    elt.ir_type == "Hash"
    some kvi
    kv := elt.value[kvi]
    kv.key.ir_type == "String"
    regex.match("(?i)^(encrypt|encryption|algorithm|cipher|hash)$", kv.key.value)
    kv.value.ir_type == "String"
    check_weak_string(kv.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak algorithm in array structure. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := {n |
        walk(parent, [_, n])
        n.ir_type == "Attribute"
    }
    attr := attrs[_]
    regex.match("(?i).*cipher.*|.*mode.*", attr.name)
    attr.value.ir_type == "String"
    some mode
    weak_modes[mode]
    regex.match(sprintf("(?i).*%s.*", [mode]), attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak cipher mode detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := {n |
        walk(parent, [_, n])
        n.ir_type == "Variable"
    }
    var := vars[_]
    regex.match("(?i).*cipher.*|.*mode.*", var.name)
    var.value.ir_type == "String"
    some mode
    weak_modes[mode]
    regex.match(sprintf("(?i).*%s.*", [mode]), var.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak cipher mode in variable. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    func_calls := {n |
        walk(parent, [_, n])
        n.ir_type == "FunctionCall"
    }
    fc := func_calls[_]
    is_weak_func_name(fc.name)
    result := {
        "type": "sec_weak_crypt",
        "element": fc,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak cryptographic function call. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    method_calls := {n |
        walk(parent, [_, n])
        n.ir_type == "MethodCall"
    }
    mc := method_calls[_]
    is_weak_func_name(mc.method)
    result := {
        "type": "sec_weak_crypt",
        "element": mc,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak cryptographic method call. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    accesses := {n |
        walk(parent, [_, n])
        n.ir_type == "Access"
    }
    acc := accesses[_]
    acc.right.ir_type == "String"
    regex.match("(?i).*md5.*|.*sha1.*|.*des.*|.*crypt.*", acc.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": acc,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak algorithm referenced in data access. (CWE-327)"
    }
}