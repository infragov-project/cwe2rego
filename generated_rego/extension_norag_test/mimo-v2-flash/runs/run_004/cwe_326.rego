package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC4", "AES-128", "AES128", "MD5", "SHA1", "SHA-1", "SHA128", "RSA1024", "DSA1024", "ECDSA1024"}
outdated_protocols := {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1", "TLS1", "TLS1.0", "TLS1.1"}
weak_settings := {"none", "false", "disabled", "no", "off", "0", "SSE-S3"}
weak_key_sizes := {64, 80, 1024, 512, 256}

check_weak_string(str) {
    some i
    weak := weak_algorithms[i]
    regex.match(sprintf("(?i).*%s.*", [weak]), str)
} else {
    some i
    weak := outdated_protocols[i]
    regex.match(sprintf("(?i).*%s.*", [weak]), str)
} else {
    some i
    weak := weak_settings[i]
    regex.match(sprintf("(?i).*%s.*", [weak]), str)
}

check_weak_value(value) {
    value.ir_type == "String"
    check_weak_string(value.value)
} else {
    value.ir_type == "FunctionCall"
    check_weak_string(value.name)
} else {
    value.ir_type == "VariableReference"
    check_weak_string(value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    attr_name := node.name
    attr_value := node.value
    
    algorithm_attrs := {"algorithm", "cipher", "encryption_type", "encryption_mode", "hash_algorithm", "mac_algorithm", "signature_algorithm", "digest", "hash", "cipher_suites", "crypto", "keyspec", "encrypt"}
    
    attr_name == algorithm_attrs[_]
    check_weak_value(attr_value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption algorithm detected - Avoid using weak algorithms like DES, 3DES, RC4, or AES-128. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    attr_name := node.name
    attr_value := node.value
    
    key_length_attrs := {"key_length", "key_size", "modulus_length", "bit_length", "key_bits", "rsa_bits", "strength", "bits"}
    
    attr_name == key_length_attrs[_]
    attr_value.ir_type == "Integer"
    weak_key_sizes[_] == attr_value.value
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Insufficient key length - Keys below 128 bits or RSA below 2048 bits are vulnerable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    attr_name := node.name
    attr_value := node.value
    
    protocol_attrs := {"protocol", "tls_version", "ssl_policy", "min_protocol_version", "ssl_version", "tls_protocol", "ssl_protocol"}
    
    attr_name == protocol_attrs[_]
    check_weak_value(attr_value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Outdated protocol detected - Avoid using SSLv3, TLSv1.0, or TLSv1.1. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    attr_name := node.name
    attr_value := node.value
    
    key_attrs := {"secret_key", "password", "token", "encryption_key", "static_iv", "secret", "auth_key", "api_key", "secret_token", "auth_password", "api_secret", "passphrase"}
    
    attr_name == key_attrs[_]
    attr_value.ir_type == "String"
    attr_value.value != ""
    not glitch_lib.traverse_var(attr_value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Hardcoded encryption key - Keys should not be hardcoded in code. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    attr_name := node.name
    attr_value := node.value
    
    encryption_attrs := {"encryption_enabled", "server_side_encryption", "customer_managed_key", "encrypted", "enable_encryption", "use_encryption", "encryption", "crypto_enabled", "enable_crypto", "kms_key_id"}
    
    attr_name == encryption_attrs[_]
    (attr_value.ir_type == "Boolean" and attr_value.value == false) or
    (attr_value.ir_type == "String" and check_weak_string(attr_value.value))
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Misconfigured encryption - Encryption is disabled or using weak settings. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    var_name := node.name
    var_value := node.value
    
    # Check for weak algorithm in variable names and values
    check_weak_value(var_value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption algorithm detected in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    
    # Check function calls for weak algorithms
    check_weak_value(node)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption function detected. (CWE-326)"
    }
}