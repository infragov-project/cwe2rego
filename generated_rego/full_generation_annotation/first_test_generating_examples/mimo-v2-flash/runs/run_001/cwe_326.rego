package glitch

import data.glitch_lib

# Weak cryptographic patterns
weak_algorithms := {"DES", "3DES", "RC4", "AES-128", "Blowfish", "SHA-1", "MD5", "SHA1", "RC4-SHA", "DES-CBC3-SHA", "AES128-SHA", "arcfour", "3des-cbc", "sha1"}
deprecated_protocols := {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLS_1_0", "TLS_1_1", "TLSv1", "TLSv1.1"}
weak_ciphers := {"RC4", "CBC", "NULL", "EXPORT", "DES", "3DES", "MD5", "SHA1"}
insecure_modes := {"ECB"}

# Keywords indicating cryptographic settings
algorithm_keywords := {"algorithm", "cipher", "encryption_method", "protocol", "ssl_cipher", "ssl_protocol"}
key_size_keywords := {"key_length", "key_size", "bits", "size"}
protocol_keywords := {"protocol", "tls_version", "ssl_policy", "ssl_protocols", "ssl_protocol"}
ciphers_keywords := {"ciphers", "cipher_suites", "security_policy", "ssl_ciphers", "ssl_cipher", "line"}
secret_keywords := {"secret_key", "api_key", "password", "initialization_vector"}
iv_keywords := {"iv", "salt", "initialization_vector"}
kdf_keywords := {"kdf", "pbkdf2_iterations", "scrypt_cost", "hashing_algorithm", "digest"}
mode_keywords := {"mode", "block_mode"}

# Helper: Check if a string value contains weak patterns
contains_weak_pattern(value, pattern_set) {
    value.ir_type == "String"
    pattern := pattern_set[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), value.value)
}

# Helper: Check for insufficient key sizes
is_insufficient_key_size(value, threshold) {
    value.ir_type == "Integer"
    value.value < threshold
} else {
    value.ir_type == "String"
    to_number(value.value) < threshold
}

# Rule 1: Weak algorithms in attributes (e.g., ssl_cipher, ssl_protocol)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    algorithm_keywords[attr.name]
    contains_weak_pattern(attr.value, weak_algorithms)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected (CWE-326)"
    }
}

# Rule 2: Insufficient key sizes (e.g., key_size: 1024)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    key_size_keywords[attr.name]
    is_insufficient_key_size(attr.value, 2048)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key size (CWE-326)"
    }
}

# Rule 3: Deprecated protocols (e.g., ssl_protocol: TLSv1 TLSv1.1)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    protocol_keywords[attr.name]
    contains_weak_pattern(attr.value, deprecated_protocols)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Deprecated protocol detected (CWE-326)"
    }
}

# Rule 4: Insecure cipher suites (e.g., ssl_ciphers: RC4-SHA:DES-CBC3-SHA)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    ciphers_keywords[attr.name]
    contains_weak_pattern(attr.value, weak_ciphers)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure cipher suite detected (CWE-326)"
    }
}

# Rule 5: Weak password hash (MD5 $1$)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "password"
    attr.value.ir_type == "String"
    regex.match("^\\$1\\$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak password hash - MD5 detected (CWE-326)"
    }
}

# Rule 6: Fixed IVs
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    iv_keywords[attr.name]
    attr.value.ir_type == "String"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Fixed initialization vector (CWE-326)"
    }
}

# Rule 7: Weak KDF hashes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    kdf_keywords[attr.name]
    contains_weak_pattern(attr.value, weak_algorithms)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak KDF hash detected (CWE-326)"
    }
}

# Rule 8: Insecure modes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    mode_keywords[attr.name]
    contains_weak_pattern(attr.value, insecure_modes)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure mode of operation (CWE-326)"
    }
}

# Rule 9: Weak algorithms in command lines (OpenSSL commands with weak algorithms)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "command"
    attr.value.ir_type == "String"
    contains_weak_pattern(attr.value, weak_algorithms)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak algorithm in command (CWE-326)"
    }
}

# Rule 10: Insufficient key size in command lines (OpenSSL 1024)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "command"
    attr.value.ir_type == "String"
    regex.match("genrsa.*\\s1024(\\s|$)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "RSA key size 1024 is too small (CWE-326)"
    }
}