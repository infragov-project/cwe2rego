package glitch

import data.glitch_lib

is_path(str) {
    regex.match("^[a-zA-Z]:\\\\", str)
} else {
    regex.match("^/", str)
} else {
    regex.match("^[a-zA-Z]+://", str)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    weak_algorithm_names := {"algorithm", "cipher", "encryption_algorithm", "ssl_ciphers", "cipher_suites", "crypto_algorithm"}
    weak_algorithm_values := {"DES", "3DES", "RC4", "AES128", "MD5", "SHA1", "DES-CBC3-SHA", "RC4-SHA", "AES128-SHA"}
    some name
    weak_algorithm_names[name]
    attr.name == name
    attr.value.ir_type == "String"
    glitch_lib.contains(attr.value.value, weak_algorithm_values[_])
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm used - This may allow attackers to crack encryption more easily. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    rsa_key_names := {"rsa_bits", "rsa_key_size", "key_size", "key_length", "size"}
    some name
    rsa_key_names[name]
    attr.name == name
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient RSA key length - RSA keys should be at least 2048 bits. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    aes_key_names := {"aes_key_length", "key_length", "size"}
    some name
    aes_key_names[name]
    attr.name == name
    attr.value.ir_type == "Integer"
    attr.value.value < 256
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient AES key length - AES keys should be at least 256 bits. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    protocol_names := {"ssl_protocol", "min_tls_version", "protocols", "tls_version", "ssl_protocols"}
    weak_protocols := {"TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "SSLv2.0", "SSLv3.0", "TLSv1", "TLSv1.1"}
    some name
    protocol_names[name]
    attr.name == name
    attr.value.ir_type == "String"
    glitch_lib.contains(attr.value.value, weak_protocols[_])
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Outdated protocol used - Deprecated protocols like TLS 1.0 or SSLv3 should not be used. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    protocol_names := {"ssl_protocol", "min_tls_version", "protocols", "tls_version", "ssl_protocols"}
    weak_protocols := {"TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "SSLv2.0", "SSLv3.0", "TLSv1", "TLSv1.1"}
    some name
    protocol_names[name]
    attr.name == name
    attr.value.ir_type == "Array"
    some i
    elem := attr.value.value[i]
    elem.ir_type == "String"
    glitch_lib.contains(elem.value, weak_protocols[_])
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Outdated protocol used in array - Deprecated protocols like TLS 1.0 or SSLv3 should not be used. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    cipher_mode_names := {"cipher_mode", "mode_of_operation"}
    weak_cipher_modes := {"ECB", "CBC"}
    some name
    cipher_mode_names[name]
    attr.name == name
    attr.value.ir_type == "String"
    glitch_lib.contains(attr.value.value, weak_cipher_modes[_])
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Misconfigured cipher mode - Weak modes like ECB or CBC without authentication should be avoided. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    secret_names := {"secret_key", "salt", "initialization_vector", "iv", "secret", "password", "crypto_key"}
    some name
    secret_names[name]
    attr.name == name
    attr.value.ir_type == "String"
    not is_path(attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded secret - Hardcoded keys, salts, or IVs should be avoided. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "content"
    attr.value.ir_type == "String"
    regex.match("default_bits\\s*=\\s*1024[^\\n]*\\n", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak key length in configuration - RSA keys should be at least 2048 bits. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "content"
    attr.value.ir_type == "String"
    regex.match("default_md\\s*=\\s*sha1[^\\n]*\\n", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak hash algorithm in configuration - SHA1 should not be used. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    vars := glitch_lib.all_variables(node)
    var := vars[_]
    weak_var_names := {"algorithm", "cipher", "encryption_algorithm", "ssl_ciphers", "cipher_suites", "crypto_algorithm"}
    weak_algorithm_values := {"DES", "3DES", "RC4", "AES128", "MD5", "SHA1", "DES-CBC3-SHA", "RC4-SHA", "AES128-SHA", "AES-128-CBC", "RC4-SHA"}
    some name
    weak_var_names[name]
    glitch_lib.contains(var.name, name)
    var.value.ir_type == "String"
    glitch_lib.contains(var.value.value, weak_algorithm_values[_])
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Weak encryption algorithm used - This may allow attackers to crack encryption more easily. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    vars := glitch_lib.all_variables(node)
    var := vars[_]
    protocol_names := {"ssl_protocol", "min_tls_version", "protocols", "tls_version", "ssl_protocols", "min_version"}
    weak_protocols := {"TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "SSLv2.0", "SSLv3.0", "TLSv1", "TLSv1.1"}
    some name
    protocol_names[name]
    glitch_lib.contains(var.name, name)
    var.value.ir_type == "String"
    glitch_lib.contains(var.value.value, weak_protocols[_])
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Outdated protocol used - Deprecated protocols like TLS 1.0 or SSLv3 should not be used. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    vars := glitch_lib.all_variables(node)
    var := vars[_]
    secret_names := {"secret_key", "salt", "initialization_vector", "iv", "secret", "password", "crypto_key"}
    some name
    secret_names[name]
    glitch_lib.contains(var.name, name)
    var.value.ir_type == "String"
    not is_path(var.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Hardcoded secret - Hardcoded keys, salts, or IVs should be avoided. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "vars"
    attr.value.ir_type == "Hash"
    some i
    pair := attr.value.value[i]
    key := pair.key
    value := pair.value
    key.ir_type == "String"
    value.ir_type == "String"
    weak_algorithm_keys := {"crypto_algorithm", "algorithm", "cipher"}
    weak_algorithm_values := {"DES", "3DES", "RC4", "AES128", "MD5", "SHA1", "DES-CBC3-SHA", "RC4-SHA", "AES128-SHA", "3DES"}
    some key_name
    weak_algorithm_keys[key_name]
    key.value == key_name
    glitch_lib.contains(value.value, weak_algorithm_values[_])
    result := {
        "type": "sec_weak_crypt",
        "element": value,
        "path": parent.path,
        "description": "Weak encryption algorithm used in vars - This may allow attackers to crack encryption more easily. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "vars"
    attr.value.ir_type == "Hash"
    some i
    pair := attr.value.value[i]
    key := pair.key
    value := pair.value
    key.ir_type == "String"
    value.ir_type == "String"
    secret_keys := {"crypto_key", "secret_key", "salt", "initialization_vector", "iv", "secret", "password"}
    some key_name
    secret_keys[key_name]
    key.value == key_name
    not is_path(value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": value,
        "path": parent.path,
        "description": "Hardcoded secret in vars - Hardcoded keys, salts, or IVs should be avoided. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "vars"
    attr.value.ir_type == "Hash"
    some i
    pair := attr.value.value[i]
    key := pair.key
    value := pair.value
    key.ir_type == "String"
    value.ir_type == "String"
    protocol_keys := {"tls_version", "ssl_protocol", "min_tls_version", "protocols"}
    weak_protocols := {"TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "SSLv2.0", "SSLv3.0"}
    some key_name
    protocol_keys[key_name]
    key.value == key_name
    glitch_lib.contains(value.value, weak_protocols[_])
    result := {
        "type": "sec_weak_crypt",
        "element": value,
        "path": parent.path,
        "description": "Outdated protocol used in vars - Deprecated protocols like TLS 1.0 or SSLv3 should not be used. (CWE-326)"
    }
}