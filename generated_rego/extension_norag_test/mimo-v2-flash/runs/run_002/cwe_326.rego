package glitch

import data.glitch_lib

# Define weak patterns based on CWE-326
weak_encryption_pattern := "(?i)\\b(DES|3DES|RC4|AES-128|RSA-1024|MD5|SHA-1)\\b"
weak_protocol_pattern := "(?i)\\b(SSLv2|SSLv3|TLS[\\s-]?1\\.[01])\\b"
weak_cipher_pattern := "(?i)\\b(CBC|DES|3DES|MD5|NULL|EXPORT)\\b"

# Rule for weak encryption/protocols in attributes (including nested values)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    # Check for weak encryption patterns in attribute values
    glitch_lib.traverse(attr.value, weak_encryption_pattern)
    # Exclude false positives from shell commands that use OpenSSL with strong algorithms
    not is_false_positive(attr)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected. (CWE-326)"
    }
}

# Rule for weak protocol versions in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    # Check for weak protocol patterns in attribute values
    glitch_lib.traverse(attr.value, weak_protocol_pattern)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak protocol version detected. (CWE-326)"
    }
}

# Rule for weak cipher suites in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    # Check for weak cipher patterns in attribute values
    glitch_lib.traverse(attr.value, weak_cipher_pattern)
    # Exclude false positives from shell commands that use OpenSSL with strong algorithms
    not is_false_positive(attr)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cipher suite detected. (CWE-326)"
    }
}

# Rule for weak encryption/protocols in variables (including nested values)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    # Check for weak encryption patterns in variable values
    glitch_lib.traverse(var.value, weak_encryption_pattern)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Weak encryption algorithm detected in variable. (CWE-326)"
    }
}

# Rule for weak protocol versions in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    # Check for weak protocol patterns in variable values
    glitch_lib.traverse(var.value, weak_protocol_pattern)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Weak protocol version detected in variable. (CWE-326)"
    }
}

# Rule for weak cipher suites in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    # Check for weak cipher patterns in variable values
    glitch_lib.traverse(var.value, weak_cipher_pattern)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Weak cipher suite detected in variable. (CWE-326)"
    }
}

# Additional rule for insufficient key length (specific to key-related attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    # Check if attribute name suggests key length
    regex.match("(?i)(key_length|key_size|bit_strength|key_bits)", attr.name)
    # Check if value is an integer less than 128 for symmetric or 2048 for asymmetric
    attr.value.ir_type == "Integer"
    attr.value.value < 128
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    # Check if variable name suggests key length
    regex.match("(?i)(key_length|key_size|bit_strength|key_bits)", var.name)
    # Check if value is an integer less than 128 for symmetric or 2048 for asymmetric
    var.value.ir_type == "Integer"
    var.value.value < 128
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Insufficient key length detected in variable. (CWE-326)"
    }
}

# Helper function to exclude false positives
is_false_positive(attr) {
    # Exclude cases where the attribute is a shell command using OpenSSL with strong algorithm (AES-256-CBC) and weak digest (MD5)
    attr.value.ir_type == "Sum"
    glitch_lib.traverse(attr.value, "(?i)aes-256-cbc")
    glitch_lib.traverse(attr.value, "(?i)md5")
}