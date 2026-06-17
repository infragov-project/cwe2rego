package glitch

import data.glitch_lib
import future.keywords.in

command_attributes := {"shell", "command", "exec", "script"}

weak_encryption_pattern := "(?i)\\bDES\\b|\\b3DES\\b|\\bRC2\\b|\\bRC4\\b|\\bBLOWFISH\\b|\\bAES-?ECB\\b|\\bDES-CBC\\b|\\bAES-CBC\\b|\\bTLS_RSA_WITH_AES_128_CBC_SHA\\b|\\bTLS_RSA_WITH_AES_256_CBC_SHA\\b"
weak_hashing_pattern := "(?i)md5|md5_crypt|\\bSHA1\\b|\\bSHA-1\\b"
deprecated_protocol_pattern := "(?i)\\bSSLv2\\b|\\bSSLv3\\b|\\bTLS\\s*1\\.0\\b|\\bTLS\\s*1\\.1\\b"

matches_pattern(node, pattern) {
    node.ir_type == "String"
    regex.match(pattern, node.value)
}

matches_pattern(node, pattern) {
    node.ir_type == "Access"
    node.right.ir_type == "String"
    regex.match(pattern, node.right.value)
}

matches_pattern(node, pattern) {
    node.ir_type == "FunctionCall"
    regex.match(pattern, node.name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    not attr.name in command_attributes
    walk(attr.value, [_, node])
    matches_pattern(node, weak_encryption_pattern)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak encryption algorithm - Avoid using broken or risky cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := glitch_lib.all_variables(parent)[_]
    walk(var.value, [_, node])
    matches_pattern(node, weak_encryption_pattern)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak encryption algorithm - Avoid using broken or risky cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    not attr.name in command_attributes
    walk(attr.value, [_, node])
    matches_pattern(node, weak_hashing_pattern)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak hashing algorithm - Avoid using broken or risky cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := glitch_lib.all_variables(parent)[_]
    walk(var.value, [_, node])
    matches_pattern(node, weak_hashing_pattern)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak hashing algorithm - Avoid using broken or risky cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := glitch_lib.all_attributes(parent)[_]
    not attr.name in command_attributes
    walk(attr.value, [_, node])
    matches_pattern(node, deprecated_protocol_pattern)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of deprecated protocol - Avoid using deprecated SSL/TLS protocols. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := glitch_lib.all_variables(parent)[_]
    walk(var.value, [_, node])
    matches_pattern(node, deprecated_protocol_pattern)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of deprecated protocol - Avoid using deprecated SSL/TLS protocols. (CWE-327)"
    }
}