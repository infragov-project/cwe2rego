package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC4", "Blowfish", "CAST", "MD5", "SHA-1", "SSLv2", "SSLv3", "TLS_1_0", "TLS_1_1", "ECB"}

key_size_names := {"key_size", "keylength", "key_length", "rsa_key_size"}

weak_key_size_max := 2048

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.value.ir_type == "String"
    algorithm_value := attr.value.value
    some weak_alg in weak_algorithms
    glitch_lib.contains(algorithm_value, weak_alg)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name in key_size_names
    attr.value.ir_type == "Integer"
    attr.value.value < weak_key_size_max
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "RSA key size less than 2048 bits (CWE-327)"
    }
}