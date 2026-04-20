package glitch

import data.glitch_lib

crypto_keywords := {"algorithm", "cipher", "hash", "ssl", "tls", "key", "encrypt", "protocol", "signature", "mac", "digest", "md5_crypt"}

weak_algorithms := {"md5", "sha1", "des", "3des", "rc4", "blowfish", "aes[-_ ]?128", "ecb", "sslv2", "sslv3", "tls_[-_ ]?1\\.0", "tls_[-_ ]?1\\.1", "rsa[-_ ]?1024", "sunx509", "md5_crypt"}

crypto_function_names := {"hash", "encrypt", "md5", "sha1", "filter|hash", "filter|md5"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    regex.match(crypto_keywords[_], node.name)
    glitch_lib.traverse(node.value, crypto_keywords[_])
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cryptographic algorithm in configuration. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    regex.match(crypto_keywords[_], node.name)
    glitch_lib.traverse(node.value, crypto_keywords[_])
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cryptographic algorithm in variable. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    regex.match(crypto_function_names[_], node.name)
    walk(node, [_, leaf])
    leaf.ir_type == "String"
    regex.match(weak_algorithms[_], leaf.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cryptographic algorithm in function call. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.name == "key_length"
    walk(node.value, [_, leaf])
    leaf.ir_type == "Integer"
    leaf.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak key length used. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.name == "key_algorithm"
    walk(node.value, [_, leaf])
    leaf.ir_type == "String"
    regex.match(weak_algorithms[_], leaf.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak key algorithm used. (CWE-327)"
    }
}