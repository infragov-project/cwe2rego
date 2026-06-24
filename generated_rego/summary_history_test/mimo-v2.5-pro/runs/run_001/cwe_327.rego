package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC4", "RC2", "MD4", "MD5", "SHA1", "SHA-1", "SHA-224", "RIPEMD160", "ECB", "CBC", "OFB", "XOR", "ROT-25", "RSA-1024", "md5_crypt"}

weak_protocols := {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1", "WEP", "WPA", "WPA-TKIP"}

all_weak := weak_algorithms | weak_protocols

crypto_keywords := {"algorithm", "cipher", "encryption", "encrypt", "decrypt", "hash", "digest", "tls", "ssl", "crypto", "signing", "auth", "password", "passwd", "key", "secret", "token", "passphrase", "salt"}

has_crypto_keyword(name) {
    lower_name := lower(name)
    keyword := crypto_keywords[_]
    contains(lower_name, keyword)
}

build_pattern(items) = result {
    terms := [t | t := items[_]]
    result := sprintf("(?i)(%s)", [concat("|", terms)])
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    pattern := build_pattern(all_weak)
    regex.match(pattern, node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak or broken cryptographic algorithm or protocol. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "MethodCall"
    pattern := build_pattern(all_weak)
    regex.match(pattern, node.method)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak or broken cryptographic algorithm or protocol. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    has_crypto_keyword(attr.name)
    pattern := build_pattern(all_weak)
    walk(attr.value, [_, v])
    v.ir_type == "String"
    regex.match(pattern, v.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of weak or broken cryptographic algorithm or protocol. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    has_crypto_keyword(var.name)
    pattern := build_pattern(all_weak)
    walk(var.value, [_, v])
    v.ir_type == "String"
    regex.match(pattern, v.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of weak or broken cryptographic algorithm or protocol. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    pair := hash_node.value[_]
    pair.key.ir_type == "String"
    has_crypto_keyword(pair.key.value)
    pattern := build_pattern(all_weak)
    walk(pair.value, [_, v])
    v.ir_type == "String"
    regex.match(pattern, v.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of weak or broken cryptographic algorithm or protocol. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    has_crypto_keyword(node.name)
    pattern := build_pattern(all_weak)
    arg := node.args[_]
    walk(arg, [_, v])
    v.ir_type == "String"
    regex.match(pattern, v.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak or broken cryptographic algorithm or protocol in function call. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "MethodCall"
    has_crypto_keyword(node.method)
    pattern := build_pattern(all_weak)
    arg := node.args[_]
    walk(arg, [_, v])
    v.ir_type == "String"
    regex.match(pattern, v.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak or broken cryptographic algorithm or protocol in method call. (CWE-327)"
    }
}