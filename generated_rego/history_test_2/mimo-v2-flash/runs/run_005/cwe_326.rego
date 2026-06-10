package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC4", "Blowfish", "AES-128", "ARC4", "MD5", "SHA1", "SHA-1", "ECB"}
weak_key_lengths := {1024, 128, 64}
key_length_attributes := {"key_length", "key_size", "size", "min_rsa_key_size", "bit_length"}
encryption_disabled_values := {"false", "disabled", "none", "null"}
encryption_attributes := {"encryption_enabled", "enable_encryption", "storage_encrypted", "ssl_enabled", "http_enforce", "use_encryption"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.value.ir_type == "String"
    glitch_lib.contains(attr.value.value, weak_algorithms[_])
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm - Avoid using deprecated or broken cryptographic algorithms. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name in key_length_attributes
    attr.value.ir_type == "Integer"
    attr.value.value in weak_key_lengths
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length - Avoid using weak key lengths for cryptographic algorithms. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name in encryption_attributes
    attr.value.ir_type == "String"
    attr.value.value in encryption_disabled_values
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled - Avoid disabling encryption features. (CWE-326)"
    }
}