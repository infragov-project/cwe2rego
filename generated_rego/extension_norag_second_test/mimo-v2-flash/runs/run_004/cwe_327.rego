package glitch

import data.glitch_lib

weak_algorithm_patterns := {
    "(?i)\\bmd5\\b",
    "(?i)\\bsha1\\b",
    "(?i)\\bsha-1\\b",
    "(?i)\\bhmac[-_]?md5\\b",
    "(?i)\\bhmac[-_]?sha1\\b",
    "(?i)\\bmd5_crypt\\b",
    "(?i)\\bdes\\b",
    "(?i)\\b3des\\b",
    "(?i)\\brc4\\b",
    "(?i)\\bblowfish\\b",
    "(?i)\\btwofish\\b",
    "(?i)\\baes[-_]?128\\b",
    "(?i)\\bsslv2\\b",
    "(?i)\\bsslv3\\b",
    "(?i)\\btls[-_]?1[-_]?0\\b",
    "(?i)\\btls[-_]?1[-_]?1\\b",
    "(?i)\\btls_1_2\\b",
    "(?i)\\becb\\b"
}

cryptographic_attributes := {
    "algorithm", "cipher", "encryption_algorithm", "sse_algorithm", "encryption_type",
    "hash_algorithm", "signature_algorithm", "digest_algorithm", "ssl_policy",
    "protocol_version", "tls_version", "min_protocol_version",
    "mode", "block_cipher_mode", "encryption_mode",
    "key_length", "key_size", "bit_length",
    "algorithm_type", "custom_algorithm", "private_cipher",
    "policy", "security_policy", "crypto_policy",
    "encrypt", "cipher_suites"
}

is_weak_algorithm(str) {
    pattern := weak_algorithm_patterns[_]
    regex.match(pattern, str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    cryptographic_attributes[node.name]
    walk(node.value, [_, subnode])
    subnode.ir_type == "String"
    is_weak_algorithm(subnode.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using weak, deprecated, or insecure cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    walk(node.value, [_, subnode])
    subnode.ir_type == "String"
    is_weak_algorithm(subnode.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using weak, deprecated, or insecure cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    walk(node, [_, subnode])
    subnode.ir_type == "String"
    is_weak_algorithm(subnode.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using weak, deprecated, or insecure cryptographic algorithms. (CWE-327)"
    }
}