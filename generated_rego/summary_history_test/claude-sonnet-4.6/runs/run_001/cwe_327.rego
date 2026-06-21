package glitch

import data.glitch_lib

cipher_name_pattern := "(?i).*(cipher|encrypt|decrypt|hash|digest|algorithm|ssl|tls|signing|signature|integrity|mac|key_spec|protect|ike|vpn|auth).*"

weak_algo_pattern := "(?i).*(\\bDES\\b|\\b3DES\\b|\\bTripleDES\\b|\\bRC[245]\\b|\\bBlowfish\\b|\\bIDEA\\b|\\bSEED\\b|\\bTEA\\b|\\bECB\\b|eNULL|aNULL|\\bNULL\\b|\\bEXPORT\\b|\\bMD[45]|\\bSHA[-_]?1\\b|_SHA(?:[,\\]\\s]|$)|HMAC-MD5|HMAC-SHA1|SHA1withRSA|MD5withRSA|\\bSSLv[23]\\b|\\bTLSv1\\.[01]\\b|\\bTLS1_[01]\\b|\\bGroup[125]\\b|\\bbase64\\b|\\bxor\\b|rot13|rot25|rot47|obfuscat|\\bplaintext\\b).*"

weak_key_sizes := {512, 768, 1024}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(cipher_name_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(weak_algo_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, v])
    v.ir_type == "Variable"
    v.value.ir_type == "String"
    regex.match(cipher_name_pattern, v.name)
    regex.match(weak_algo_pattern, v.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    regex.match(cipher_name_pattern, entry.key.value)
    entry.value.ir_type == "String"
    regex.match(weak_algo_pattern, entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, fc])
    fc.ir_type == "FunctionCall"
    regex.match("(?i).*(hash|digest|hmac|crypt).*", fc.name)
    arg := fc.args[_]
    arg.ir_type == "String"
    regex.match("(?i)^(md[245]|sha[-_]?1|sha1|des|3des|rc[245]|blowfish|idea|seed|tea)$", arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": fc,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic hash function. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, fc])
    fc.ir_type == "FunctionCall"
    regex.match("(?i)^(md[245]|sha1|sha[-_]?1|des|3des|rc[245]|blowfish|idea|seed|tea)$", fc.name)
    result := {
        "type": "sec_weak_crypt",
        "element": fc,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm as a function. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Access"
    attr.value.right.ir_type == "String"
    regex.match("(?i).*(md[245]|sha1|sha[-_]?1).*", attr.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i).*(key[_.]?(size|bits|length)|rsa[_.]?bits|modulus).*", attr.name)
    attr.value.ir_type == "Integer"
    weak_key_sizes[attr.value.value]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of an insufficient asymmetric key size. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i).*(encrypt|is_encrypted|in_transit_encrypt).*", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption is explicitly disabled. (CWE-327)"
    }
}