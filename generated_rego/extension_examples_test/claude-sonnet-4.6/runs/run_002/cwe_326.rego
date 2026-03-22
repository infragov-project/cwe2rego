package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, fc])
    fc.ir_type == "FunctionCall"
    regex.match("(?i)^(md[245]|sha[-_]?1|des_?crypt|md5_?crypt)$", fc.name)
    result := {
        "type": "sec_weak_crypt",
        "element": fc,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak hash function called directly. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, fc])
    fc.ir_type == "FunctionCall"
    regex.match("(?i)(hash|checksum|digest)", fc.name)
    arg := fc.args[_]
    arg.ir_type == "String"
    regex.match("(?i)^(md[245]|sha[-_]?1)$", arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": fc,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak hash algorithm in function call. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    regex.match("(?i)^(encrypt|cipher|hash_algorithm|digest_algorithm)$", entry.key.value)
    entry.value.ir_type == "String"
    regex.match("(?i)(md[245]|sha[-_]?1|des|3des|rc[245]|blowfish|md5_crypt|des_crypt)", entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak algorithm in hash entry. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match("(?i)cipher_?suite", v.name)
    v.value.ir_type == "String"
    regex.match("(?i)(NULL|EXPORT|ANON|_DES|_RC4|_3DES|_MD5|_SHA[^0-9]|_SHA$)", v.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cipher suite in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)cipher_?suite", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)(NULL|EXPORT|ANON|_DES|_RC4|_3DES|_MD5|_SHA[^0-9]|_SHA$)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cipher suite in attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(algorithm|cipher|sse_algorithm|server_side_encryption|encryption_algorithm)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)(^|[^A-Za-z])(DES|3DES|TRIPLE.?DES|RC2|RC4|RC5|BLOWFISH|IDEA)([^A-Za-z]|$)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak encryption algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(hash_?algorithm|digest_?algorithm|signature_?algorithm|mac_?algorithm|signing_?algorithm)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)(MD[245]|SHA[-_]?1[^0-9]|SHA[-_]?1$)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak hash function in cryptographic context. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "auth_method"
    attr.value.ir_type == "String"
    regex.match("(?i)^(md5|md4|sha[-_]?1|des)$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak authentication method. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(ssl_?policy|security_?policy|ssl_?protocol|tls_?version|minimum_?protocol_?version|minimum_?tls_?version|protocol_?version)", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)(SSLv?[23]|TLSv?1\\.0|TLSv?1\\.1|TLS[-_]1[-_][01]|201[456])", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Deprecated TLS/SSL protocol. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(rsa_?bits|modulus_?size|dh_?param_?size)", attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value > 0
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Asymmetric key size below 2048 bits. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)(key_?size|key_?bits|bit_?length|encryption_?key_?size)", attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value > 0
    attr.value.value < 128
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Symmetric key size below 128 bits. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Access"
    attr.value.right.ir_type == "String"
    regex.match("(?i)(md5|sha1|des_crypt|md5_crypt)", attr.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Accessing value with weak hash identifier. (CWE-326)"
    }
}