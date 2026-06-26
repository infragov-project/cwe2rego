package glitch

import data.glitch_lib

key_size_attr_names := {"rsa_bits", "key_size", "key_length", "bits"}

weak_algo_pattern := "(?i).*(\\bdes\\b|\\brc2\\b|\\brc4\\b|\\barcfour\\b|3des|triple.des|\\bblowfish\\b|sslv2|sslv3|tlsv1\\.0|tlsv1\\.1|tls_1_0|tls_1_1|ssl_3_0|ssl_2_0|sha.?1|md5|md5_crypt|cbc_sha).*"

weak_func_name_pattern := "(?i)^(md5|sha1|sha_1|des|rc4|rc2|arcfour)$"

crypto_name_pattern := "(?i).*(algorithm|cipher|encrypt|crypto|ssl_protocol|tls_protocol|cipher_suite|\\bhash\\b|digest|auth_method|auth_type|\\bprotocol\\b).*"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    lower(node.name) == key_size_attr_names[_]
    node.value.ir_type == "Integer"
    node.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Encryption key size is too small. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    regex.match(crypto_name_pattern, node.name)
    node.value.ir_type == "String"
    regex.match(weak_algo_pattern, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Use of weak encryption algorithm or protocol detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    regex.match(crypto_name_pattern, node.name)
    node.value.ir_type == "String"
    regex.match(weak_algo_pattern, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Use of weak encryption algorithm in variable. (CWE-326)"
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
        "description": "Inadequate encryption strength - Use of weak cryptographic function. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    arg := node.args[_]
    arg.ir_type == "String"
    regex.match(weak_algo_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Use of weak algorithm in function argument. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "Access"
    node.value.right.ir_type == "String"
    regex.match(weak_algo_pattern, node.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm referenced in data access. (CWE-326)"
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
    regex.match(weak_algo_pattern, entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Inadequate encryption strength - Use of weak encryption algorithm in configuration. (CWE-326)"
    }
}