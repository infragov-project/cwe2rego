package glitch

import data.glitch_lib

weak_algorithm_pattern := "\\b(DES|3DES|RC4|MD5|SHA1|SHA-1|ECB|CBC|TEA|XOR|ROT-25|AES[-_]?128)\\b"
weak_protocol_pattern := "\\b(SSL|TLS[ _]?1[._]0|TLS[ _]?1[._]1|SSLv2|SSLv3)\\b"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    (regex.match(weak_algorithm_pattern, node.value) or regex.match(weak_protocol_pattern, node.value))
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm or protocol - Avoid using broken or risky cryptographic algorithms or protocols. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    (regex.match(weak_algorithm_pattern, node.name) or regex.match(weak_protocol_pattern, node.name))
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm or protocol in function call - Avoid using broken or risky cryptographic algorithms or protocols. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    arg := node.args[_]
    arg.ir_type == "String"
    (regex.match(weak_algorithm_pattern, arg.value) or regex.match(weak_protocol_pattern, arg.value))
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm or protocol in function call argument - Avoid using broken or risky cryptographic algorithms or protocols. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    item := node.value[_]
    item.key.ir_type == "String"
    (regex.match(weak_algorithm_pattern, item.key.value) or regex.match(weak_protocol_pattern, item.key.value))
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm or protocol in hash key - Avoid using broken or risky cryptographic algorithms or protocols. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    item := node.value[_]
    item.value.ir_type == "String"
    (regex.match(weak_algorithm_pattern, item.value.value) or regex.match(weak_protocol_pattern, item.value.value))
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm or protocol in hash value - Avoid using broken or risky cryptographic algorithms or protocols. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Access"
    node.right.ir_type == "String"
    (regex.match(weak_algorithm_pattern, node.right.value) or regex.match(weak_protocol_pattern, node.right.value))
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm or protocol in accessed attribute - Avoid using broken or risky cryptographic algorithms or protocols. (CWE-327)"
    }
}