package glitch

import data.glitch_lib

# Define weak values for different attributes
weak_key_sizes := {1024, 128}
weak_algorithms := {"AES-128", "DES", "3DES", "RC4", "Plaintext", "Unencrypted", "TRIPLE-DES", "RSAES_PKCS1_V1_5"}
weak_protocols := {"SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1"}
weak_ssl_policies := {"ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-2015-05", "TLS-1-0", "SSL-3-0"}
weak_status_values := {"false", "disabled", "none", "unencrypted"}

# Check for weak integer values (e.g., key sizes)
check_weak_integer(value) {
    value.ir_type == "Integer"
    weak_key_sizes[value.value]
}

# Check for weak string values
check_weak_string(value, weak_set) {
    value.ir_type == "String"
    weak_set[value.value]
}

# Rule for weak key sizes in key management
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "key_size"
    check_weak_integer(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Key size is too small (CWE-326)"
    }
}

# Rule for weak algorithms in storage or key management
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name in {"algorithm", "cipher", "key_spec"}
    check_weak_string(attr.value, weak_algorithms)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak algorithm specified (CWE-326)"
    }
}

# Rule for weak protocols in network encryption
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name in {"protocol", "min_tls_version"}
    check_weak_string(attr.value, weak_protocols)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak protocol version (CWE-326)"
    }
}

# Rule for weak SSL policies
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name in {"ssl_policy", "security_policy"}
    check_weak_string(attr.value, weak_ssl_policies)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak SSL policy (CWE-326)"
    }
}

# Rule for weak status flags (e.g., encryption disabled)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name in {"encryption", "enabled", "storage_encryption"}
    check_weak_string(attr.value, weak_status_values)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Encryption disabled or weak (CWE-326)"
    }
}