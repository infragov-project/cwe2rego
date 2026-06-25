package glitch

import data.glitch_lib

weak_crypto_ids := {
    "des", "3des", "tdea", "rc4", "rc2", "blowfish", "idea", "xor",
    "rot[-_]13", "rot[-_]25", "md2", "md4", "md5", "sha[-_]?0", "sha[-_]?1",
    "sslv2", "sslv3", "tlsv1\\.0", "tlsv1\\.1", "ecb",
    "rc4-sha", "des-cbc3?-sha", "null-md5", "export",
    "md5withrsa", "sha1withrsa", "plaintext", "base64", "caesar",
    "rsa[-_]?1024", "dsa[-_]?1024", "dh[-_]?1024", "cbc",
}

weak_crypto_pattern := sprintf("(%s)", [concat("|", weak_crypto_ids)])

crypto_name_keywords := {
    "cipher", "encrypt", "hash", "digest", "ssl", "tls", "sign",
    "crypt", "algorithm", "protocol", "auth", "password", "passwd",
}

insecure_flag_attrs := {"verify_ssl", "tls_insecure", "insecure"}

is_weak_crypto_string(s) {
    regex.match(weak_crypto_pattern, lower(s))
}

name_has_crypto_keyword(name) {
    keyword := crypto_name_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [keyword]), name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    {"Attribute", "Variable"}[node.ir_type]
    name_has_crypto_keyword(node.name)
    walk(node.value, [_, child])
    child.ir_type == "String"
    is_weak_crypto_string(child.value)
    result := {
        "type": "sec_weak_crypt",
        "element": child,
        "path": parent.path,
        "description": "Weak or broken cryptographic algorithm detected - Avoid using obsolete, insecure, or deprecated cryptographic primitives. (CWE-327)",
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    name_has_crypto_keyword(entry.key.value)
    walk(entry.value, [_, child])
    child.ir_type == "String"
    is_weak_crypto_string(child.value)
    result := {
        "type": "sec_weak_crypt",
        "element": child,
        "path": parent.path,
        "description": "Weak or broken cryptographic algorithm detected - Avoid using obsolete, insecure, or deprecated cryptographic primitives. (CWE-327)",
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    func_has_weak_crypto(node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak or broken cryptographic algorithm detected - Avoid using obsolete, insecure, or deprecated cryptographic primitives. (CWE-327)",
    }
}

func_has_weak_crypto(node) {
    is_weak_crypto_string(node.name)
}

func_has_weak_crypto(node) {
    arg := node.args[_]
    arg.ir_type == "String"
    is_weak_crypto_string(arg.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    {"Attribute", "Variable"}[node.ir_type]
    insecure_flag_attrs[lower(node.name)]
    node.value.ir_type == "Boolean"
    node.value.value == true
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak or broken cryptographic algorithm detected - Avoid using obsolete, insecure, or deprecated cryptographic primitives. (CWE-327)",
    }
}