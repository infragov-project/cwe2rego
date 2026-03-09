package glitch

import data.glitch_lib

# 1. Detect weak encryption algorithms in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "algorithm"
    attr.value.ir_type == "String"
    weak_algorithms := {"aes-128", "des", "3des", "rc4", "blowfish", "sha-1", "md5"}
    lower(attr.value.value) == weak_algorithms[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "encryption_algorithm"
    attr.value.ir_type == "String"
    weak_algorithms := {"aes-128", "des", "3des", "rc4", "blowfish", "sha-1", "md5"}
    lower(attr.value.value) == weak_algorithms[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "sse_algorithm"
    attr.value.ir_type == "String"
    weak_algorithms := {"aes-128", "des", "3des", "rc4", "blowfish", "sha-1", "md5"}
    lower(attr.value.value) == weak_algorithms[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "encryption_type"
    attr.value.ir_type == "String"
    weak_algorithms := {"aes-128", "des", "3des", "rc4", "blowfish", "sha-1", "md5"}
    lower(attr.value.value) == weak_algorithms[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "cipher_suite"
    attr.value.ir_type == "String"
    weak_algorithms := {"aes-128", "des", "3des", "rc4", "blowfish", "sha-1", "md5"}
    lower(attr.value.value) == weak_algorithms[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)."
    }
}

# 2. Detect insufficient key lengths
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "rsa_key_size"
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient RSA key length (< 2048 bits) (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "ec_key_size"
    attr.value.ir_type == "Integer"
    attr.value.value < 224
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient ECC key length (< 224 bits) (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "size"
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length detected (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "key_size"
    attr.value.ir_type == "Integer"
    attr.value.value <= 128
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length detected (CWE-326)."
    }
}

# 3. Detect deprecated TLS/SSL versions
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "tls_version"
    attr.value.ir_type == "String"
    weak_versions := {"tls 1.0", "tls 1.1", "ssl 2.0", "ssl 3.0", "tlsv1", "tlsv1.0", "tlsv1.1", "sslv2.0", "sslv3.0"}
    lower(attr.value.value) == weak_versions[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Deprecated TLS/SSL version detected (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "ssl_protocol"
    attr.value.ir_type == "String"
    weak_versions := {"tls 1.0", "tls 1.1", "ssl 2.0", "ssl 3.0", "tlsv1", "tlsv1.0", "tlsv1.1", "sslv2.0", "sslv3.0"}
    lower(attr.value.value) == weak_versions[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Deprecated TLS/SSL version detected (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "min_tls_version"
    attr.value.ir_type == "String"
    weak_versions := {"tls 1.0", "tls 1.1", "ssl 2.0", "ssl 3.0", "tlsv1", "tlsv1.0", "tlsv1.1", "sslv2.0", "sslv3.0"}
    lower(attr.value.value) == weak_versions[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Deprecated TLS/SSL version detected (CWE-326)."
    }
}

# 4. Detect weak cipher suites in content
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "content"
    attr.value.ir_type == "String"
    
    # Use regex to find weak cipher suites in the content
    regex.match("(?i)ssl.*cipher.*(rc4|des-cbc3|3des|null)", attr.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cipher suite detected in configuration content (CWE-326)."
    }
}

# 5. Detect disabled encryption in content
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "content"
    attr.value.ir_type == "String"
    
    # Use regex to find disabled encryption in the content
    regex.match("(?i)encryption_enabled:\\s*false", attr.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption explicitly disabled in configuration content (CWE-326)."
    }
}

# 6. Detect weak encryption algorithm in content
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "content"
    attr.value.ir_type == "String"
    
    # Use regex to find weak encryption algorithm in the content
    regex.match("(?i)encryption_algorithm:\\s*none", attr.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm specified in configuration content (CWE-326)."
    }
}

# 7. Detect disabled encryption at rest (Boolean)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "encryption_enabled"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption at rest is disabled (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "storage_encryption"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption at rest is disabled (CWE-326)."
    }
}

# 8. Detect weak encryption at rest algorithms (String)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "storage_encryption"
    attr.value.ir_type == "String"
    weak_algorithms := {"aes-128", "des", "3des", "rc4", "blowfish", "sha-1", "md5", "none"}
    lower(attr.value.value) == weak_algorithms[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm for at rest (CWE-326)."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "encryption_algorithm"
    attr.value.ir_type == "String"
    weak_algorithms := {"aes-128", "des", "3des", "rc4", "blowfish", "sha-1", "md5", "none"}
    lower(attr.value.value) == weak_algorithms[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm for at rest (CWE-326)."
    }
}