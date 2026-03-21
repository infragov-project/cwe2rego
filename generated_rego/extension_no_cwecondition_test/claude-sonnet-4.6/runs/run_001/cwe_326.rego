package glitch

import data.glitch_lib

weak_algo_pattern := "(?i)^(md5|sha1|sha-1|des|3des|rc2|rc4|md5_crypt|des_crypt|bigcrypt|bsdicrypt|sha1_crypt)$"
weak_cipher_pattern := "(?i)(_SHA[^0-9a-zA-Z_]|_SHA$|\\bDES\\b|\\bRC4\\b|\\bRC2\\b|\\bMD5\\b)"
weak_in_name := "(?i).*(md5|sha1|sha-1).*"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    regex.match(weak_algo_pattern, node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak hash/encryption function used. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    regex.match("(?i).*(hash|crypt|encrypt).*", node.name)
    arg := node.args[_]
    arg.ir_type == "String"
    regex.match(weak_algo_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak algorithm in hash/encrypt function. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    regex.match("(?i)^(auth_method|encrypt|algorithm)$", node.name)
    node.value.ir_type == "String"
    regex.match(weak_algo_pattern, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak auth/encryption method configured. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    entry.key.value == "encrypt"
    entry.value.ir_type == "String"
    regex.match(weak_algo_pattern, entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak encryption scheme in configuration. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "Access"
    node.value.right.ir_type == "String"
    regex.match(weak_in_name, node.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Attribute accesses value hashed with weak algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "String"
    regex.match("(?i).*cipher_suite.*", node.name)
    regex.match(weak_cipher_pattern, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cipher suite in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "String"
    regex.match("(?i).*cipher_suite.*", node.name)
    regex.match(weak_cipher_pattern, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cipher suite in attribute. (CWE-326)"
    }
}