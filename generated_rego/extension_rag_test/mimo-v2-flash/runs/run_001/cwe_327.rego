package glitch

import data.glitch_lib

crypto_attribute_names := {
    "ssl_policy", "cipher", "encryption_algorithm", "crypto_key", "kms_key_spec",
    "customer_master_key_spec", "sse_algorithm", "encryption_type", "auth_mechanism",
    "protocol_versions", "min_tls_version", "max_tls_version", "ciphers", "cipher_suites",
    "signature_algorithm", "hash_algorithm", "password_hash", "security_policy",
    "tls_security_policy", "encryption_policy", "crypto_policy", "enable_ssl", "use_tls",
    "require_encryption", "secure_transport", "legacy_protocol_enabled", "encrypt"
}

weak_value_patterns := [
    "DES", "3DES", "RC4", "MD5", "md5", "SHA-1", "sha1", "SHA1", "AES-ECB", "AES-CBC", "RSA-1024",
    "DSA-1024", "ECDSA-192", "BLOWFISH", "ARCFOUR", "ARC4", "SSL", "SSLv2", "SSLv3",
    "TLS 1.0", "TLS 1.1", "TLSv1", "TLSv1.0", "TLSv1.1", "HMAC-MD5", "HMAC-SHA1",
    "RSA-MD5", "DSA-SHA1", "ECDSA-SHA1", "ECB", "CBC", "custom_algorithm",
    "proprietary_encryption", "obfuscation", "xor", "md5_crypt"
]

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    crypto_attribute_names[attr.name]
    glitch_lib.traverse(attr.value, weak_value_patterns)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or weak cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    atomic_unit := atomic_units[_]
    attrs := glitch_lib.all_attributes(atomic_unit)
    attr := attrs[_]
    crypto_attribute_names[attr.name]
    glitch_lib.traverse(attr.value, weak_value_patterns)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or weak cryptographic algorithm (CWE-327)"
    }
}