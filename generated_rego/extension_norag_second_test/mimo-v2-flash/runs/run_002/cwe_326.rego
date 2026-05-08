package glitch

import data.glitch_lib

# Weak cryptographic standards detection
weak_algorithms := {"rc4", "des", "3des", "aes-128", "ecb", "rsa-1024", "dsa", "sha1", "md5", "pbkdf1", "md5_crypt", "md5_crypt", "md5", "sha1"}

check_weak_value(value) {
    value.ir_type == "String"
    lower_value := lower(value.value)
    regex.match("(rc4|des|3des|aes-128|ecb|rsa-1024|dsa|sha1|md5|pbkdf1|md5_crypt)", lower_value)
}

check_weak_value(value) {
    value.ir_type == "Integer"
    value.value == 1024
}

# Specialized check for Ansible filter functions
check_function_filter(value) {
    value.ir_type == "FunctionCall"
    value.name == "filter|hash"
    count(value.args) >= 2
    value.args[1].ir_type == "String"
    lower_arg := lower(value.args[1].value)
    regex.match("(sha1|md5)", lower_arg)
}

# Specialized check for Ansible cipher suites strings
check_cipher_suite(value) {
    value.ir_type == "String"
    regex.match(".*TLS_RSA_WITH_AES_128.*", value.value)
}

# Helper to traverse complex values (Sum, Hash, Array) to find primitive weaknesses
find_weakness_in_complex(complex_val) {
    complex_val.ir_type == "Sum"
    check_weak_value(complex_val.left)
} else {
    complex_val.ir_type == "Sum"
    check_weak_value(complex_val.right)
} else {
    complex_val.ir_type == "Sum"
    find_weakness_in_complex(complex_val.left)
} else {
    complex_val.ir_type == "Sum"
    find_weakness_in_complex(complex_val.right)
} else {
    complex_val.ir_type == "FunctionCall"
    check_function_filter(complex_val)
} else {
    complex_val.ir_type == "String"
    check_cipher_suite(complex_val)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes (Ansible/Chef/Puppet)
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name != ""
    
    lower_name := lower(attr.name)
    weak_attr_names := {"algorithm", "cipher", "encryption_type", "encryption_algorithm", "kms_key_spec", "key_spec", "protocol", "version", "min_tls_version", "key_length", "key_size", "modulus", "rsa_key_bits", "encrypt", "hash_algorithm", "kdf", "cipher_suites", "salt_size", "store_type"}
    
    weak_attr_names[lower_name]
    
    # Check direct value or recurse into complex structures
    check_weak_value(attr.value) 
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic standards detected in configuration. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes (Ansible/Chef/Puppet) - Complex Values
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name != ""
    
    lower_name := lower(attr.name)
    weak_attr_names := {"algorithm", "cipher", "encryption_type", "encryption_algorithm", "kms_key_spec", "key_spec", "protocol", "version", "min_tls_version", "key_length", "key_size", "modulus", "rsa_key_bits", "encrypt", "hash_algorithm", "kdf", "cipher_suites", "salt_size", "store_type"}
    
    weak_attr_names[lower_name]
    
    # Check complex structures (Sum, FunctionCall)
    find_weakness_in_complex(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic standards detected in configuration. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables (Chef/Puppet)
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.name != ""
    
    lower_name := lower(var.name)
    weak_attr_names := {"algorithm", "cipher", "encryption_type", "encryption_algorithm", "kms_key_spec", "key_spec", "protocol", "version", "min_tls_version", "key_length", "key_size", "modulus", "rsa_key_bits", "encrypt", "hash_algorithm", "kdf", "cipher_suites", "salt_size", "store_type"}
    
    weak_attr_names[lower_name]
    
    # Check direct value or recurse into complex structures
    check_weak_value(var.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic standards detected in variable definition. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables (Chef/Puppet) - Complex Values
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.name != ""
    
    lower_name := lower(var.name)
    weak_attr_names := {"algorithm", "cipher", "encryption_type", "encryption_algorithm", "kms_key_spec", "key_spec", "protocol", "version", "min_tls_version", "key_length", "key_size", "modulus", "rsa_key_bits", "encrypt", "hash_algorithm", "kdf", "cipher_suites", "salt_size", "store_type"}
    
    weak_attr_names[lower_name]
    
    # Check complex structures
    find_weakness_in_complex(var.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic standards detected in variable definition. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for disabled encryption
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    attr.value.ir_type == "Boolean"
    lower_name := lower(attr.name)
    disabled_attr_names := {"enabled", "encryption_enabled", "storage_encryption", "require_client_auth"}
    
    disabled_attr_names[lower_name]
    attr.value.value == false
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Lack of encryption enforcement - Encryption is explicitly disabled. (CWE-326)"
    }
}