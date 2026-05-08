package glitch

import data.glitch_lib

# Weak encryption algorithms, protocols, and hashes
weak_ciphers := {"des", "3des", "rc4", "blowfish", "rc2", "aes-128", "md5", "sha-1", "sha1"}
weak_protocols := {"sslv2", "sslv3", "tls1", "tls1.0", "tls1.1", "tls 1.0", "tls 1.1"}

# Helper to check if a string contains weak crypto material
is_weak_crypto(val) {
    val.ir_type == "String"
    lower_val := lower(val.value)
    # Check for weak algorithms/hashes
    regex.match("(?i).*(des|3des|rc4|blowfish|rc2|md5|sha[-_]?1).*", lower_val)
}

is_weak_crypto(val) {
    val.ir_type == "String"
    lower_val := lower(val.value)
    # Check for weak protocols or key sizes in string form
    regex.match("(?i).*(sslv[23]|tls[-_ ]?1[.01]?).*", lower_val)
}

# Helper to check for insufficient key lengths (RSA/AES)
is_weak_key_length(val) {
    val.ir_type == "Integer"
    val.value < 2048
}

# Rule 1: Detect weak encryption attributes (Ansible, Chef, Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check attribute name for crypto-related keywords
    attr_name_lower := lower(attr.name)
    regex.match("(?i).*(cipher|algorithm|ssl|tls|hash|digest|key_size|encrypt).*", attr_name_lower)
    
    # Check value for weak crypto
    is_weak_crypto(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm or protocol detected (CWE-326)"
    }
}

# Rule 2: Detect insufficient key lengths
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check attribute name for key size keywords
    attr_name_lower := lower(attr.name)
    regex.match("(?i).*(key_size|key_length|rsa|modulus).*", attr_name_lower)
    
    # Check value for insufficient key length
    is_weak_key_length(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient encryption key length (CWE-326)"
    }
}

# Rule 3: Detect weak encryption in variables (Chef/Puppet attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_vars := glitch_lib.all_variables(parent)
    var := all_vars[_]
    
    # Check variable name for crypto-related keywords
    var_name_lower := lower(var.name)
    regex.match("(?i).*(password|secret|key|crypto|ssl|tls|md5|sha).*", var_name_lower)
    
    # Check value for weak crypto
    is_weak_crypto(var.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Weak encryption in variable (CWE-326)"
    }
}

# Rule 4: Detect weak encryption in complex nested structures (Hash within Hash, Array, etc.)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Traverse deeply to find weak crypto in nested structures
    walk(attr.value, [path, leaf])
    is_weak_crypto(leaf)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption in nested configuration (CWE-326)"
    }
}