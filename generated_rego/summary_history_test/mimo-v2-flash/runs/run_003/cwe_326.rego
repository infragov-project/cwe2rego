package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC4", "Blowfish", "AES-128", "SHA-1", "MD5", "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "AES/ECB", "RSA-1024", "sha1", "md5", "md5_crypt"}

weak_cipher_suites := {"RSA_WITH_AES_128_CBC_SHA", "DES_CBC"}

encryption_attributes := {"algorithm", "cipher", "ssl_policy", "tls_version", "encryption", "kms_key_id", "encrypt"}

key_size_attributes := {"key_size", "key_length"}

disabled_encryption_attributes := {"encryption", "enabled", "enable_encryption"}

hardcoded_key_attributes := {"secret", "password", "encryption_key"}

cipher_suite_attributes := {"cipher_suites", "allowed_ssl_versions"}

hashing_attributes := {"hashing_algorithm", "checksum", "digest", "auth_method"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    encryption_attributes[node.name]
    node.value.ir_type == "String"
    algorithm := weak_algorithms[_]
    glitch_lib.contains(node.value.value, algorithm)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak or outdated encryption algorithm - Use of weak or outdated encryption algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    encryption_attributes[node.name]
    node.value.ir_type == "FunctionCall"
    algorithm := weak_algorithms[_]
    glitch_lib.contains(node.value.name, algorithm)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak or outdated encryption algorithm - Use of weak or outdated encryption algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    encryption_attributes[node.name]
    node.value.ir_type == "FunctionCall"
    algorithm := weak_algorithms[_]
    arg := node.value.args[_]
    arg.ir_type == "String"
    glitch_lib.contains(arg.value, algorithm)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak or outdated encryption algorithm - Use of weak or outdated encryption algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "KeyValue"
    node.key.ir_type == "String"
    encryption_attributes[node.key.value]
    node.value.ir_type == "String"
    algorithm := weak_algorithms[_]
    glitch_lib.contains(node.value.value, algorithm)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak or outdated encryption algorithm - Use of weak or outdated encryption algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key_node := pair.key
    value_node := pair.value
    key_node.ir_type == "String"
    encryption_attributes[key_node.value]
    value_node.ir_type == "String"
    algorithm := weak_algorithms[_]
    glitch_lib.contains(value_node.value, algorithm)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak or outdated encryption algorithm - Use of weak or outdated encryption algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    algorithm := weak_algorithms[_]
    glitch_lib.contains(node.name, algorithm)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak or outdated encryption algorithm - Use of weak or outdated encryption algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    algorithm := weak_algorithms[_]
    arg := node.args[_]
    arg.ir_type == "String"
    glitch_lib.contains(arg.value, algorithm)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak or outdated encryption algorithm - Use of weak or outdated encryption algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    node.value.ir_type == "FunctionCall"
    algorithm := weak_algorithms[_]
    glitch_lib.contains(node.value.name, algorithm)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak or outdated encryption algorithm - Use of weak or outdated encryption algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    node.value.ir_type == "FunctionCall"
    algorithm := weak_algorithms[_]
    arg := node.value.args[_]
    arg.ir_type == "String"
    glitch_lib.contains(arg.value, algorithm)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak or outdated encryption algorithm - Use of weak or outdated encryption algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    key_size_attributes[node.name]
    node.value.ir_type == "Integer"
    node.value.value < 2048
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Insufficient key length - Key size is below recommended standards. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    disabled_encryption_attributes[node.name]
    node.value.ir_type == "Boolean"
    node.value.value == false
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Disabled encryption - Encryption is explicitly disabled for sensitive data. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    disabled_encryption_attributes[node.name]
    node.value.ir_type == "String"
    node.value.value == "none"
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Disabled encryption - Encryption is explicitly disabled for sensitive data. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    hardcoded_key_attributes[node.name]
    node.value.ir_type == "Access"
    node.value.right.ir_type == "String"
    algorithm := weak_algorithms[_]
    glitch_lib.contains(node.value.right.value, algorithm)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Hardcoded encryption key - Use of hardcoded or static encryption keys. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    hardcoded_key_attributes[node.name]
    node.value.ir_type == "String"
    not glitch_lib.traverse_var(node.value)
    count(node.value.value) >= 16
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Hardcoded encryption key - Use of hardcoded or static encryption keys. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    cipher_suite_attributes[node.name]
    node.value.ir_type == "Array"
    element := node.value.value[_]
    element.ir_type == "String"
    cipher := weak_cipher_suites[_]
    glitch_lib.contains(element.value, cipher)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cipher suite - Use of inadequate cipher suites for TLS/SSL. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    cipher_suite_attributes[node.name]
    node.value.ir_type == "String"
    cipher := weak_cipher_suites[_]
    glitch_lib.contains(node.value.value, cipher)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cipher suite - Use of inadequate cipher suites for TLS/SSL. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    contains(node.name, "cipher_suites")
    node.value.ir_type == "String"
    cipher := weak_cipher_suites[_]
    glitch_lib.contains(node.value.value, cipher)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cipher suite - Use of inadequate cipher suites for TLS/SSL. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    hashing_attributes[node.name]
    node.value.ir_type == "String"
    algorithm := weak_algorithms[_]
    glitch_lib.contains(node.value.value, algorithm)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Deprecated hashing algorithm - Use of weak hashing algorithms like SHA-1 or MD5. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    node.name == "password"
    node.value.ir_type == "Access"
    node.value.right.ir_type == "String"
    algorithm := weak_algorithms[_]
    glitch_lib.contains(node.value.right.value, algorithm)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak or outdated encryption algorithm - Use of weak or outdated encryption algorithm. (CWE-326)"
    }
}