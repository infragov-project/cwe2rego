package glitch

import data.glitch_lib

weak_crypto_patterns := {"des", "3des", "rc4", "md5", "sha1", "sha-1", "ssl", "tls1", "tls1.0", "tls1.1", "dtls1.0", "dh-rsa", "dh-dss", "dhe-rsa", "export", "anon", "aes-ecb", "hmac-md5", "hmac-sha1", "md5_crypt"}

crypto_attributes := {"encryption_algorithm", "ssl_policy", "protocol", "signature_algorithm", "ca_cert_identifier", "storage_encrypted", "server_side_encryption_configuration", "ike_version", "key_algorithm", "cipher_suites", "hash", "digest", "encrypt", "key_size"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    crypto_attributes[node.name]
    walk(node, [_, string_node])
    string_node.ir_type == "String"
    glitch_lib.contains(string_node.value, weak_crypto_patterns[_])
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic standards. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    glitch_lib.contains(node.name, weak_crypto_patterns[_])
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic standards. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    crypto_attributes[node.name]
    walk(node, [_, string_node])
    string_node.ir_type == "String"
    glitch_lib.contains(string_node.value, weak_crypto_patterns[_])
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic standards. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.name == "key_size"
    node.value.ir_type == "Integer"
    node.value.value < 2048
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak key size - Key size less than 2048 bits is considered weak. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.name == "cipher_suites"
    walk(node, [_, string_node])
    string_node.ir_type == "String"
    glitch_lib.contains(string_node.value, weak_crypto_patterns[_])
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm in TLS/SSL policy - Avoid using deprecated or weak cryptographic standards. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.name == "ssl_policy"
    walk(node, [_, string_node])
    string_node.ir_type == "String"
    glitch_lib.contains(string_node.value, weak_crypto_patterns[_])
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm in TLS/SSL policy - Avoid using deprecated or weak cryptographic standards. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    walk(node, [path, hash_node])
    hash_node.ir_type == "String"
    glitch_lib.contains(hash_node.value, weak_crypto_patterns[_])
    
    result := {
        "type": "sec_weak_crypt",
        "element": hash_node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using deprecated or weak cryptographic standards. (CWE-327)"
    }
}