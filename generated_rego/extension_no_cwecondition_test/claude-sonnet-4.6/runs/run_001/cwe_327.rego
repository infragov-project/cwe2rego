package glitch

import data.glitch_lib

is_weak_value(v) {
    regex.match("(?i)^(des|3des|triple.{0,2}des|rc2|rc4|md5|sha1|sha-1|md4|md2|blowfish|arcfour|md5_crypt|sha1_crypt|des_crypt|bsdi_crypt|sslv2|sslv3|tlsv1|tlsv1\\.0|tls1\\.0|tls1\\.1)$", v)
}

is_weak_value(v) {
    regex.match("(?i).*(\\bdes\\b|\\brc4\\b|\\bmd5\\b|\\bsha1\\b|\\bsha-1\\b|_cbc_sha\\b|\\bsslv2\\b|\\bsslv3\\b).*", v)
}

is_crypto_name(name) {
    regex.match("(?i).*(algorithm|cipher|encrypt|hash_?type|digest|ssl_?version|tls_?version|protocol|cipher_?suite|key_?type|hash_algorithm|auth_method|auth_type|signing).*", name)
}

is_weak_func_name(name) {
    regex.match("(?i)^(md5|sha1|sha-1|des|rc4)$", name)
}

is_weak_key_name(name) {
    regex.match("(?i).*(md5|sha1|sha-1).*", name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "String"
    is_crypto_name(node.name)
    is_weak_value(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using deprecated cryptographic algorithms such as MD5, SHA1, or DES. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "String"
    is_crypto_name(node.name)
    is_weak_value(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using deprecated cryptographic algorithms such as MD5, SHA1, or DES. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    pair.key.ir_type == "String"
    is_crypto_name(pair.key.value)
    pair.value.ir_type == "String"
    is_weak_value(pair.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": pair.value,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using deprecated cryptographic algorithms such as MD5, SHA1, or DES. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    regex.match("(?i)filter\\|(hash|password_hash|checksum)", node.name)
    arg := node.args[_]
    arg.ir_type == "String"
    is_weak_value(arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using deprecated cryptographic algorithms such as MD5, SHA1, or DES. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    is_weak_func_name(node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using deprecated cryptographic algorithms such as MD5, SHA1, or DES. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "Access"
    node.value.right.ir_type == "String"
    is_weak_key_name(node.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using deprecated cryptographic algorithms such as MD5, SHA1, or DES. (CWE-327)"
    }
}