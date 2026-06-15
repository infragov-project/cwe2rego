package glitch

import data.glitch_lib

# Define weak encryption configurations
weak_algorithms := {"DES", "3DES", "RC4", "AES-128"}
weak_protocols := {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
weak_cipher_patterns := {"*CBC*", "*RC4*", "*MD5*", "*SHA1*"}
weak_key_lengths := {1024, 128}
weak_key_specs := {"RSA_1024", "DH_1024", "AES_128"}
weak_signature_algorithms := {"MD5", "SHA1"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for weak encryption algorithms in attributes
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check algorithm attribute
    attr.name == "algorithm"
    attr.value.ir_type == "String"
    algorithm := attr.value.value
    algorithm == weak_algorithms[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected - Use of deprecated or weak cryptographic algorithms (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for weak protocols in attributes
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check protocol attribute
    attr.name == "protocol"
    attr.value.ir_type == "String"
    protocol := attr.value.value
    protocol == weak_protocols[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak protocol detected - Use of deprecated or insecure protocols (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for weak cipher suites
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check cipher_suite attribute
    attr.name == "cipher_suite"
    attr.value.ir_type == "String"
    cipher := attr.value.value
    weak_pattern := weak_cipher_patterns[_]
    regex.match(weak_pattern, cipher)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cipher suite detected - Use of insecure cipher suites (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for weak key lengths
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check key_length attribute
    attr.name == "key_length"
    attr.value.ir_type == "Integer"
    key_length := attr.value.value
    key_length == weak_key_lengths[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak key length detected - Insufficient key size for cryptographic operations (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for weak key specifications
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check key_spec attribute
    attr.name == "key_spec"
    attr.value.ir_type == "String"
    key_spec := attr.value.value
    key_spec == weak_key_specs[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak key specification detected - Insufficient key size or type (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for disabled encryption
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check encryption attribute
    attr.name == "encryption"
    attr.value.ir_type == "Boolean"
    encryption_disabled := attr.value.value
    encryption_disabled == false
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled - Data is not encrypted at rest or in transit (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for missing encryption setting
    attrs := glitch_lib.all_attributes(node)
    
    # Check if encryption attribute is missing entirely
    not encryption_attribute_exists(attrs)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Missing encryption setting - No encryption configuration found for sensitive data (CWE-326)"
    }
}

encryption_attribute_exists(attrs) {
    attr := attrs[_]
    attr.name == "encryption"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for weak signature algorithms
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check signature_algorithm attribute
    attr.name == "signature_algorithm"
    attr.value.ir_type == "String"
    signature_alg := attr.value.value
    signature_alg == weak_signature_algorithms[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak signature algorithm detected - Use of broken hashing algorithms (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for disabled key rotation
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check key_rotation attribute
    attr.name == "key_rotation"
    attr.value.ir_type == "Boolean"
    key_rotation_disabled := attr.value.value
    key_rotation_disabled == false
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Key rotation disabled - Static keys without rotation mechanism (CWE-326)"
    }
}