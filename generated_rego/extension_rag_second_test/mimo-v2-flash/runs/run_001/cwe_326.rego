package glitch

import data.glitch_lib

weak_algorithms := {"AES-128", "DES", "3DES", "RC4", "RSA-1024", "SHA-1", "MD5", "md5_crypt", "md5"}
outdated_protocols := {"SSLv3", "TLS_1.0", "TLS_1.1"}
weak_hashes := {"MD5", "SHA-1", "HMAC-MD5", "md5"}
encryption_disabled_values := {"false", "disabled", "none"}
weak_ciphers := {"RC4", "3DES", "NULL", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA"}
weak_libraries := {"openssl-1.0.1", "bcrypt-1.0.0"}

weak_encryption_attr_names := {"algorithm", "encryption_algorithm", "cipher", "crypto_algorithm"}
outdated_protocol_attr_names := {"protocol", "ssl_version", "tls_version", "min_protocol_version"}
hardcoded_key_attr_names := {"key", "secret_key", "encryption_key", "master_key"}
insecure_rotation_attr_names := {"rotation", "key_rotation_period"}
disabled_encryption_attr_names := {"encryption_enabled", "encrypted", "storage_encrypted", "ssl_required"}
inadequate_cipher_attr_names := {"ciphers", "cipher_suites", "security_policy"}
non_compliant_library_attr_names := {"library_version", "crypto_provider", "dependency"}
insecure_hashing_attr_names := {"hash_algorithm", "digest", "checksum"}
weak_key_size_attr_names := {"key_size", "key_length", "rsa_key_size", "symmetric_key_length"}

check_value_contains_weak(value, weak_set) {
    value.ir_type == "String"
    count({ws | ws := weak_set[_]; contains(value.value, ws)}) > 0
} else {
    value.ir_type == "FunctionCall"
    any({check_value_contains_weak(arg, weak_set) | arg := value.args[_]})
} else {
    value.ir_type == "Access"
    check_value_contains_weak(value.right, weak_set)
} else {
    value.ir_type == "Sum"
    check_value_contains_weak(value.left, weak_set)
    check_value_contains_weak(value.right, weak_set)
} else {
    value.ir_type == "Array"
    any({check_value_contains_weak(elem, weak_set) | elem := value.value[_]})
} else {
    value.ir_type == "Hash"
    any({check_value_contains_weak(k, weak_set) | k := value.value[_]})
    any({check_value_contains_weak(v, weak_set) | v := value.value[_]})
}

check_weak_key_size(value) {
    value.ir_type == "Integer"
    value.value < 256
}

check_hardcoded_key(value) {
    value.ir_type == "String"
    value.value != ""
}

check_insecure_rotation(value) {
    value.ir_type == "Integer"
    value.value == 0
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    weak_encryption_attr_names[attr.name]
    check_value_contains_weak(attr.value, weak_algorithms)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    outdated_protocol_attr_names[attr.name]
    check_value_contains_weak(attr.value, outdated_protocols)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Outdated protocol version detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    hardcoded_key_attr_names[attr.name]
    check_hardcoded_key(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded encryption key detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    insecure_rotation_attr_names[attr.name]
    check_insecure_rotation(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure key rotation setting detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    disabled_encryption_attr_names[attr.name]
    check_value_contains_weak(attr.value, encryption_disabled_values)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption explicitly disabled (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    inadequate_cipher_attr_names[attr.name]
    check_value_contains_weak(attr.value, weak_ciphers)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate cipher suite detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    non_compliant_library_attr_names[attr.name]
    check_value_contains_weak(attr.value, weak_libraries)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Non-compliant cryptographic library detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    insecure_hashing_attr_names[attr.name]
    check_value_contains_weak(attr.value, weak_hashes)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure hashing algorithm detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    weak_key_size_attr_names[attr.name]
    check_weak_key_size(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak key size detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    node := variables[_]
    
    weak_encryption_attr_names[node.name]
    check_value_contains_weak(node.value, weak_algorithms)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    node := variables[_]
    
    outdated_protocol_attr_names[node.name]
    check_value_contains_weak(node.value, outdated_protocols)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Outdated protocol version detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    node := variables[_]
    
    hardcoded_key_attr_names[node.name]
    check_hardcoded_key(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Hardcoded encryption key detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    node := variables[_]
    
    insecure_rotation_attr_names[node.name]
    check_insecure_rotation(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Insecure key rotation setting detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    node := variables[_]
    
    disabled_encryption_attr_names[node.name]
    check_value_contains_weak(node.value, encryption_disabled_values)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Encryption explicitly disabled (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    node := variables[_]
    
    inadequate_cipher_attr_names[node.name]
    check_value_contains_weak(node.value, weak_ciphers)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate cipher suite detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    node := variables[_]
    
    non_compliant_library_attr_names[node.name]
    check_value_contains_weak(node.value, weak_libraries)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Non-compliant cryptographic library detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    node := variables[_]
    
    insecure_hashing_attr_names[node.name]
    check_value_contains_weak(node.value, weak_hashes)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Insecure hashing algorithm detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    node := variables[_]
    
    weak_key_size_attr_names[node.name]
    check_weak_key_size(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak key size detected (CWE-326)"
    }
}