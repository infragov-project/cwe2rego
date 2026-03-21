package glitch

import data.glitch_lib

weak_algorithm_values := ["DES", "3DES", "RC4", "AES-128", "Blowfish", "SHA-1", "sha1", "md5", "md5_crypt", "SunX509"]
weak_key_length_values := [1024, 128]
weak_protocol_values := ["TLS 1.0", "TLS 1.1", "SSLv3", "SSHv1", "TLS", "TLSv1"]
weak_cipher_values := ["RC4", "3DES", "MD5", "SHA1", "NULL", "EXPORT", "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA"]

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check if attribute name suggests encryption configuration
    regex.match("(?i)(algorithm|cipher|encryption|crypto|hash|encrypt)", attr.name)
    
    # Check for weak algorithm values
    attr.value.ir_type == "String"
    algorithm_value := attr.value.value
    algorithm_value == weak_algorithm_values[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm used - Avoid using deprecated or weak encryption algorithms. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check for weak algorithm in function arguments (Ansible filters, etc.)
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    regex.match("(?i)(hash|md5|sha1|encrypt|cipher)", node.name)
    
    # Check arguments for weak algorithm values
    some i
    arg := node.args[i]
    arg.ir_type == "String"
    arg_value := arg.value
    arg_value == weak_algorithm_values[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption algorithm in function call - Avoid using deprecated or weak encryption algorithms. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check for insufficient key length
    regex.match("(?i)(key_length|key_size|bits|rsa|key_size)", attr.name)
    attr.value.ir_type == "Integer"
    key_length_value := attr.value.value
    key_length_value == weak_key_length_values[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length - Use at least 2048 bits for RSA or 256 bits for AES. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check for outdated protocol versions
    regex.match("(?i)(protocol|tls|ssl|ssh|version)", attr.name)
    attr.value.ir_type == "String"
    protocol_value := attr.value.value
    protocol_value == weak_protocol_values[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Outdated protocol version - Use TLS 1.2+ or SSHv2 instead of deprecated protocols. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check for weak cipher suites in arrays
    regex.match("(?i)(cipher|suite|ciphers)", attr.name)
    attr.value.ir_type == "Array"
    element := attr.value.value[_]
    element.ir_type == "String"
    cipher_value := element.value
    cipher_value == weak_cipher_values[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cipher suite used - Avoid ciphers like RC4, 3DES, MD5, etc. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check for weak cipher suites in string values (comma-separated)
    regex.match("(?i)(cipher|suite|ciphers)", attr.name)
    attr.value.ir_type == "String"
    cipher_string := attr.value.value
    weak_cipher := weak_cipher_values[_]
    contains(cipher_string, weak_cipher)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cipher suite used - Avoid ciphers like RC4, 3DES, MD5, etc. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check for key rotation disabled
    attr.name == "key_rotation"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Key rotation disabled - Lack of key rotation exacerbates exposure. Enable key rotation. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check for hardcoded passwords/keys in sensitive contexts
    regex.match("(?i)(password|secret|key|token|credential)", attr.name)
    attr.value.ir_type == "String"
    value := attr.value.value
    # Simple heuristic: non-empty string that looks hardcoded (no variables)
    count(value) > 0
    not contains(value, "{{")
    not contains(value, "}}")
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded credential detected - Avoid storing passwords or keys directly in code. (CWE-326)"
    }
}

# Helper function to check if string contains substring
contains(str, substr) {
    regex.match(sprintf("(?i).*%s.*", [substr]), str)
}