package glitch

import data.glitch_lib

weak_crypto_pattern := `(?i).*(md4|md5|sha-?1|3des|triple.?des|rc2|rc4|blowfish|des_ecb|des_cbc|cbc_sha|sslv[23]|ssl[23]|tls[._]?1[._]?[01]|tls_v1[._]?[01]|md5.?crypt).*`

weak_algo_exact_pattern := `(?i)^(md4|md5|sha-?1|3des|triple.?des|rc2|rc4|blowfish|des|md5.?crypt)$`

weak_func_name_pattern := `(?i)^(md4|md5|sha1|sha-1|des|3des|rc2|rc4|rc5|blowfish)$`

crypto_name_pattern := `(?i).*(algorithm|cipher|hash|encrypt|decrypt|digest|crypto|protocol|ssl|tls|auth.?method|password.?hash|password.?md5).*`

crypto_func_pattern := `(?i).*(hash|digest|encrypt|cipher|hmac|crypt).*`

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "String"
    regex.match(crypto_name_pattern, node.name)
    regex.match(weak_crypto_pattern, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms such as MD5, SHA1, DES, RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "String"
    not regex.match(crypto_name_pattern, node.name)
    regex.match(weak_algo_exact_pattern, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms such as MD5, SHA1, DES, RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "Access"
    node.value.right.ir_type == "String"
    regex.match(weak_crypto_pattern, node.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms such as MD5, SHA1, DES, RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "String"
    regex.match(crypto_name_pattern, node.name)
    regex.match(weak_crypto_pattern, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms such as MD5, SHA1, DES, RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "String"
    not regex.match(crypto_name_pattern, node.name)
    regex.match(weak_algo_exact_pattern, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms such as MD5, SHA1, DES, RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "Access"
    node.value.right.ir_type == "String"
    regex.match(weak_crypto_pattern, node.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms such as MD5, SHA1, DES, RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    regex.match(crypto_name_pattern, entry.key.value)
    entry.value.ir_type == "String"
    regex.match(weak_crypto_pattern, entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.key,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms such as MD5, SHA1, DES, RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    regex.match(weak_func_name_pattern, node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms such as MD5, SHA1, DES, RC4. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    regex.match(crypto_func_pattern, node.name)
    arg := node.args[_]
    arg.ir_type == "String"
    regex.match(weak_crypto_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak or broken cryptographic algorithms such as MD5, SHA1, DES, RC4. (CWE-327)"
    }
}