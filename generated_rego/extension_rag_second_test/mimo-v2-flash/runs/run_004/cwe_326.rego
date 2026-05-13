package glitch

import data.glitch_lib

# Define weak cryptographic algorithms, protocols, and key sizes
weak_algorithms := {"DES", "3DES", "RC4", "Blowfish", "MD5", "SHA1", "AES-ECB"}
weak_protocols := {"SSLv2", "SSLv3", "TLS_1_0", "TLS_1_1", "HTTP"}
min_rsa_key_size := 2048
min_aes_key_size := 128

# Check for weak algorithm strings in values
check_weak_algorithm(val) {
    val.ir_type == "String"
    upper(val.value) == weak_algorithms[_]
}

# Check for weak protocol strings in values
check_weak_protocol(val) {
    val.ir_type == "String"
    upper(val.value) == weak_protocols[_]
}

# Check for insufficient key sizes in integers or strings
check_weak_key_size(val, name) {
    val.ir_type == "Integer"
    name == "key_size"
    val.value < min_rsa_key_size
} else {
    val.ir_type == "String"
    name == "key_size"
    regex.match(`(?i)RSA-(\d+)`, val.value)
    to_number(split(val.value, "-")[1]) < min_rsa_key_size
} else {
    val.ir_type == "String"
    name == "algorithm"
    regex.match(`(?i)AES-(\d+)`, val.value)
    to_number(split(val.value, "-")[1]) < min_aes_key_size
}

# Detect weak cryptographic configurations in attributes and variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in atomic units (Ansible/Chef/Puppet resources)
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for weak algorithms or protocols
    check_weak_algorithm(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak or broken encryption algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in atomic units (Ansible/Chef/Puppet resources)
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for weak protocols
    check_weak_protocol(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak or deprecated protocol version. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in atomic units (Ansible/Chef/Puppet resources)
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for weak key sizes
    check_weak_key_size(attr.value, attr.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Insufficient key length for cryptographic algorithm. (CWE-326)"
    }
}

# Detect weak cryptographic configurations in variables (Chef/Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables in unit blocks (Chef/Puppet attributes)
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Check for weak algorithms or protocols
    check_weak_algorithm(var.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak or broken encryption algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables in unit blocks (Chef/Puppet attributes)
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Check for weak protocols
    check_weak_protocol(var.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak or deprecated protocol version. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables in unit blocks (Chef/Puppet attributes)
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Check for weak key sizes
    check_weak_key_size(var.value, var.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Insufficient key length for cryptographic algorithm. (CWE-326)"
    }
}