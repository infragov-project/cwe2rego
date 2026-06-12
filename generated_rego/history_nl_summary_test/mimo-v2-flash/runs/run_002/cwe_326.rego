package glitch

import data.glitch_lib

weak_algorithm_pattern := "(?i)des|3des|rc4|md5|sha1|sha-1|aes-128|rsa-1024"
protocol_pattern := "(?i)ssl|sslv2|sslv3|tls1\\.0|tls1\\.1"
cipher_suite_pattern := "(?i)null|export|rc4|cbc|des"

encryption_attributes := {"algorithm", "cipher", "encryption", "key", "iv", "salt", "nonce", "kdf", "iteration", "protocol", "tls", "ssl", "fips", "nist", "compliance", "encrypt", "hash", "password", "auth_method"}

check_weak_encryption(value) {
    glitch_lib.traverse(value, weak_algorithm_pattern)
}

check_weak_protocol(value) {
    glitch_lib.traverse(value, protocol_pattern)
}

check_weak_cipher(value) {
    glitch_lib.traverse(value, cipher_suite_pattern)
}

check_insufficient_key_length(name, value) {
    glitch_lib.contains(name, encryption_attributes[_])
    value.ir_type == "Integer"
    value.value < 2048
}

check_weak_kdf(name, value) {
    glitch_lib.contains(name, encryption_attributes[_])
    value.ir_type == "Integer"
    value.value < 10000
}

check_non_compliant(name, value) {
    glitch_lib.contains(name, encryption_attributes[_])
    value.ir_type == "Boolean"
    value.value == false
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_nodes := glitch_lib.all_attributes(parent) | glitch_lib.all_variables(parent)
    node := all_nodes[_]
    
    glitch_lib.contains(node.name, encryption_attributes[_])
    check_weak_encryption(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption algorithm - Use of inadequate encryption strength. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_nodes := glitch_lib.all_attributes(parent) | glitch_lib.all_variables(parent)
    node := all_nodes[_]
    
    glitch_lib.contains(node.name, encryption_attributes[_])
    check_weak_protocol(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Insecure protocol - Use of inadequate encryption strength. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_nodes := glitch_lib.all_attributes(parent) | glitch_lib.all_variables(parent)
    node := all_nodes[_]
    
    glitch_lib.contains(node.name, encryption_attributes[_])
    check_weak_cipher(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cipher suite - Use of inadequate encryption strength. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_nodes := glitch_lib.all_attributes(parent) | glitch_lib.all_variables(parent)
    node := all_nodes[_]
    
    check_insufficient_key_length(node.name, node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Insufficient key length - Use of inadequate encryption strength. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_nodes := glitch_lib.all_attributes(parent) | glitch_lib.all_variables(parent)
    node := all_nodes[_]
    
    check_weak_kdf(node.name, node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak key derivation function - Use of inadequate encryption strength. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_nodes := glitch_lib.all_attributes(parent) | glitch_lib.all_variables(parent)
    node := all_nodes[_]
    
    check_non_compliant(node.name, node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Non-compliant encryption standard - Use of inadequate encryption strength. (CWE-326)"
    }
}