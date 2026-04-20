package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "String"
    weak_algorithm_pattern := "(?i)(DES|3DES|RC4|BLOWFISH|RSA-1024|AES-128|ECDH-P192|ECDSA-P192|SHA-1)"
    regex.match(weak_algorithm_pattern, n.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Variable"
    algorithm_attrs := {"algorithm", "encryption_algorithm", "crypto_algorithm", "cipher_algorithm", "kms_algorithm"}
    algorithm_attrs[n.name]
    n.value.ir_type == "String"
    weak_algorithm_pattern := "(?i)(DES|3DES|RC4|BLOWFISH|RSA-1024|AES-128|ECDH-P192|ECDSA-P192|SHA-1)"
    regex.match(weak_algorithm_pattern, n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Variable"
    key_size_attrs := {"key_size", "key_length", "key_bits", "key_spec"}
    key_size_attrs[n.name]
    n.value.ir_type == "Integer"
    key_size := n.value.value
    key_size < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Insufficient key size detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Variable"
    key_spec_attrs := {"key_spec", "key_type"}
    key_spec_attrs[n.name]
    n.value.ir_type == "String"
    weak_curve_pattern := "(?i)(P-192|prime192v1|secp192r1)"
    regex.match(weak_curve_pattern, n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak ECC curve detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Variable"
    protocol_attrs := {"protocol", "tls_version", "ssl_policy", "min_tls_version", "ssl_protocol"}
    protocol_attrs[n.name]
    n.value.ir_type == "String"
    weak_protocol_pattern := "(?i)(SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1)"
    regex.match(weak_protocol_pattern, n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Outdated protocol detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Variable"
    cipher_attrs := {"cipher_suites", "ciphers", "ssl_ciphers", "tls_ciphers"}
    cipher_attrs[n.name]
    n.value.ir_type == "String"
    weak_cipher_pattern := "(?i)(DES|RC4|3DES|MD5|SHA1|CBC)"
    regex.match(weak_cipher_pattern, n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak cipher suite detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Variable"
    kdf_attrs := {"key_derivation_function", "kdf", "salt"}
    kdf_attrs[n.name]
    n.value.ir_type == "String"
    weak_kdf_pattern := "(?i)(PBKDF1|PBKDF2|fixed|0x00|0x0+)"
    regex.match(weak_kdf_pattern, n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak key management detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Variable"
    misconfig_attrs := {"encrypted", "enable_encryption", "encryption_type", "storage_encryption", "fips_enabled"}
    misconfig_attrs[n.name]
    n.value.ir_type == "Boolean"
    n.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Encryption misconfiguration detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Attribute"
    algorithm_attrs := {"algorithm", "encryption_algorithm", "crypto_algorithm", "cipher_algorithm", "kms_algorithm"}
    algorithm_attrs[n.name]
    n.value.ir_type == "String"
    weak_algorithm_pattern := "(?i)(DES|3DES|RC4|BLOWFISH|RSA-1024|AES-128|ECDH-P192|ECDSA-P192|SHA-1)"
    regex.match(weak_algorithm_pattern, n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Attribute"
    key_size_attrs := {"key_size", "key_length", "key_bits", "key_spec"}
    key_size_attrs[n.name]
    n.value.ir_type == "Integer"
    key_size := n.value.value
    key_size < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Insufficient key size detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Attribute"
    protocol_attrs := {"protocol", "tls_version", "ssl_policy", "min_tls_version", "ssl_protocol"}
    protocol_attrs[n.name]
    n.value.ir_type == "String"
    weak_protocol_pattern := "(?i)(SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1)"
    regex.match(weak_protocol_pattern, n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Outdated protocol detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Attribute"
    cipher_attrs := {"cipher_suites", "ciphers", "ssl_ciphers", "tls_ciphers"}
    cipher_attrs[n.name]
    n.value.ir_type == "String"
    weak_cipher_pattern := "(?i)(DES|RC4|3DES|MD5|SHA1|CBC)"
    regex.match(weak_cipher_pattern, n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak cipher suite detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Attribute"
    misconfig_attrs := {"encrypted", "enable_encryption", "encryption_type", "storage_encryption", "fips_enabled"}
    misconfig_attrs[n.name]
    n.value.ir_type == "Boolean"
    n.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Encryption misconfiguration detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "FunctionCall"
    weak_algorithm_pattern := "(?i)(DES|3DES|RC4|BLOWFISH|RSA-1024|AES-128|ECDH-P192|ECDSA-P192|SHA-1)"
    regex.match(weak_algorithm_pattern, n.name)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "FunctionCall"
    weak_algorithm_pattern := "(?i)(DES|3DES|RC4|BLOWFISH|RSA-1024|AES-128|ECDH-P192|ECDSA-P192|SHA-1)"
    arg := n.args[_]
    arg.ir_type == "String"
    regex.match(weak_algorithm_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "MethodCall"
    weak_algorithm_pattern := "(?i)(DES|3DES|RC4|BLOWFISH|RSA-1024|AES-128|ECDH-P192|ECDSA-P192|SHA-1)"
    regex.match(weak_algorithm_pattern, n.method)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "MethodCall"
    weak_algorithm_pattern := "(?i)(DES|3DES|RC4|BLOWFISH|RSA-1024|AES-128|ECDH-P192|ECDSA-P192|SHA-1)"
    arg := n.args[_]
    arg.ir_type == "String"
    regex.match(weak_algorithm_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "FunctionCall"
    key_size_attrs := {"key_size", "key_length", "key_bits", "key_spec"}
    key_size_attrs[n.name]
    arg := n.args[_]
    arg.ir_type == "Integer"
    key_size := arg.value
    key_size < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Insufficient key size detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "MethodCall"
    key_size_attrs := {"key_size", "key_length", "key_bits", "key_spec"}
    key_size_attrs[n.method]
    arg := n.args[_]
    arg.ir_type == "Integer"
    key_size := arg.value
    key_size < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Insufficient key size detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "FunctionCall"
    protocol_attrs := {"protocol", "tls_version", "ssl_policy", "min_tls_version", "ssl_protocol"}
    protocol_attrs[n.name]
    arg := n.args[_]
    arg.ir_type == "String"
    weak_protocol_pattern := "(?i)(SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1)"
    regex.match(weak_protocol_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Outdated protocol detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "MethodCall"
    protocol_attrs := {"protocol", "tls_version", "ssl_policy", "min_tls_version", "ssl_protocol"}
    protocol_attrs[n.method]
    arg := n.args[_]
    arg.ir_type == "String"
    weak_protocol_pattern := "(?i)(SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1)"
    regex.match(weak_protocol_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Outdated protocol detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "FunctionCall"
    cipher_attrs := {"cipher_suites", "ciphers", "ssl_ciphers", "tls_ciphers"}
    cipher_attrs[n.name]
    arg := n.args[_]
    arg.ir_type == "String"
    weak_cipher_pattern := "(?i)(DES|RC4|3DES|MD5|SHA1)"
    regex.match(weak_cipher_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak cipher suite detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "MethodCall"
    cipher_attrs := {"cipher_suites", "ciphers", "ssl_ciphers", "tls_ciphers"}
    cipher_attrs[n.method]
    arg := n.args[_]
    arg.ir_type == "String"
    weak_cipher_pattern := "(?i)(DES|RC4|3DES|MD5|SHA1)"
    regex.match(weak_cipher_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak cipher suite detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "FunctionCall"
    kdf_attrs := {"key_derivation_function", "kdf", "salt"}
    kdf_attrs[n.name]
    arg := n.args[_]
    arg.ir_type == "String"
    weak_kdf_pattern := "(?i)(PBKDF1|PBKDF2|fixed|0x00|0x0+)"
    regex.match(weak_kdf_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak key management detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "MethodCall"
    kdf_attrs := {"key_derivation_function", "kdf", "salt"}
    kdf_attrs[n.method]
    arg := n.args[_]
    arg.ir_type == "String"
    weak_kdf_pattern := "(?i)(PBKDF1|PBKDF2|fixed|0x00|0x0+)"
    regex.match(weak_kdf_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak key management detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "FunctionCall"
    cipher_attrs := {"cipher_suites", "ciphers", "ssl_ciphers", "tls_ciphers"}
    cipher_attrs[n.name]
    arg := n.args[_]
    arg.ir_type == "String"
    weak_cipher_pattern := "(?i)(DES|RC4|3DES|MD5|SHA1)"
    regex.match(weak_cipher_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak cipher suite detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "MethodCall"
    cipher_attrs := {"cipher_suites", "ciphers", "ssl_ciphers", "tls_ciphers"}
    cipher_attrs[n.method]
    arg := n.args[_]
    arg.ir_type == "String"
    weak_cipher_pattern := "(?i)(DES|RC4|3DES|MD5|SHA1)"
    regex.match(weak_cipher_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak cipher suite detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "FunctionCall"
    kdf_attrs := {"key_derivation_function", "kdf", "salt"}
    kdf_attrs[n.name]
    arg := n.args[_]
    arg.ir_type == "String"
    weak_kdf_pattern := "(?i)(PBKDF1|PBKDF2|fixed|0x00|0x0+)"
    regex.match(weak_kdf_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak key management detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "MethodCall"
    kdf_attrs := {"key_derivation_function", "kdf", "salt"}
    kdf_attrs[n.method]
    arg := n.args[_]
    arg.ir_type == "String"
    weak_kdf_pattern := "(?i)(PBKDF1|PBKDF2|fixed|0x00|0x0+)"
    regex.match(weak_kdf_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak key management detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "FunctionCall"
    misconfig_attrs := {"encrypted", "enable_encryption", "encryption_type", "storage_encryption", "fips_enabled"}
    misconfig_attrs[n.name]
    arg := n.args[_]
    arg.ir_type == "Boolean"
    arg.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Encryption misconfiguration detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "MethodCall"
    misconfig_attrs := {"encrypted", "enable_encryption", "encryption_type", "storage_encryption", "fips_enabled"}
    misconfig_attrs[n.method]
    arg := n.args[_]
    arg.ir_type == "Boolean"
    arg.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Encryption misconfiguration detected (CWE-326)"
    }
}