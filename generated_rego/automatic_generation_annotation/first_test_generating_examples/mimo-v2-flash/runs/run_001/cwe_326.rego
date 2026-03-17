package glitch

import data.glitch_lib

# CWE-326: Inadequate Encryption Strength

# Patterns for weak cryptographic configurations
weak_algorithms := {"DES", "3DES", "RC4", "AES-128", "RSA-1024", "ECDSA-P-160", "SHA-1", "MD5", "BLOWFISH", "TWOFISH-128"}
inadequate_key_sizes := {"1024", "224", "128", "160"}
outdated_protocols := {"SSLv2", "SSLv3", "TLS1.0", "TLS1.1", "TLS_1_0", "TLS_1_1"}
weak_ciphers := {"CBC", "RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "SHA-1"}
predictable_keys := {"password123", "static_value", "hardcoded-secret", "aVeryWeakAndStaticHardcodedSecretKeyForEncryption"}
misconfigured_encryption := {"DISABLED", "false", "unencrypted"}
outdated_standards := {"FIPS_140_2", "legacy", "old_standard"}

# Relevant attribute names for cryptography
crypto_attrs := {"algorithm", "encryption_algorithm", "cipher", "key_spec", "key_size", "key_length", "bits", "protocol", "protocol_version", "tls_version", "ssl_policy", "security_policy", "cipher_suite", "ciphers", "key", "secret", "salt", "nonce", "initialization_vector", "encryption_enabled", "enable_encryption", "default_encryption", "security_standard", "compliance_mode", "fips_mode", "encryption", "encryption_type", "crypto_policy"}

# Helper to check if a string matches a list of patterns
matches_pattern(val, patterns) {
    regex.match(sprintf("(?i).*(%s).*", [concat("|", patterns)]), val)
}

# Check a single node (String or Integer)
check_node(node, patterns) {
    node.ir_type == "String"
    matches_pattern(node.value, patterns)
} {
    node.ir_type == "Integer"
    val_str := sprintf("%d", [node.value])
    matches_pattern(val_str, patterns)
}

# Check attributes for weak crypto values
# We only check the direct value of the attribute, not nested structures, to avoid false positives
check_attributes(attrs, patterns) {
    attr := attrs[_]
    crypto_attrs[_] == attr.name
    check_node(attr.value, patterns)
}

# Main detection rules
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    check_attributes(attrs, weak_algorithms)
    result := {
        "type": "sec_weak_crypt",
        "element": attrs[_],
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    check_attributes(attrs, inadequate_key_sizes)
    result := {
        "type": "sec_weak_crypt",
        "element": attrs[_],
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Inadequate key length detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    check_attributes(attrs, outdated_protocols)
    result := {
        "type": "sec_weak_crypt",
        "element": attrs[_],
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Outdated protocol detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    check_attributes(attrs, weak_ciphers)
    result := {
        "type": "sec_weak_crypt",
        "element": attrs[_],
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher suite detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    check_attributes(attrs, predictable_keys)
    result := {
        "type": "sec_weak_crypt",
        "element": attrs[_],
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Predictable or hardcoded key detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    check_attributes(attrs, misconfigured_encryption)
    result := {
        "type": "sec_weak_crypt",
        "element": attrs[_],
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Misconfigured or disabled encryption detected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    check_attributes(attrs, outdated_standards)
    result := {
        "type": "sec_weak_crypt",
        "element": attrs[_],
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Outdated cryptographic standard detected (CWE-326)"
    }
}