package glitch

import data.glitch_lib

weak_encryption_algorithms := {"des", "3des", "triple-des", "desede", "rc4", "arcfour", "arc2", "aes-ecb", "blowfish", "twofish"}
weak_hashing_algorithms := {"md2", "md4", "md5", "sha1", "sha-1", "sha-128", "sha-224", "ripemd160"}
insecure_protocols := {"ssl", "ssl-2", "ssl-3", "tls-1-0", "tls-1-1", "ssh-1", "http"}
insecure_cipher_patterns := {"null", "anon", "anonymous", "export", "rc4", "des", "3des", "md5", "sha1", "cbc"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in {"algorithm", "encryption_algorithm", "cipher", "kms_key_spec", "encryption_type"}
    attr.value.ir_type == "String"
    glitch_lib.contains(attr.value.value, weak_encryption_algorithms[_])
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in {"hash_algorithm", "signature_algorithm", "digest", "checksum_algorithm"}
    attr.value.ir_type == "String"
    glitch_lib.contains(attr.value.value, weak_hashing_algorithms[_])
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in {"protocol", "ssl_policy", "min_tls_version", "max_tls_version", "security_policy", "load_balancer_protocol", "listener_protocol"}
    attr.value.ir_type == "String"
    glitch_lib.contains(attr.value.value, insecure_protocols[_])
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in {"enabled_cipher_suites", "cipher_blacklist", "security_options"}
    attr.value.ir_type == "String"
    glitch_lib.contains(attr.value.value, insecure_cipher_patterns[_])
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in {"key_length", "key_size"}
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm (CWE-327)"
    }
}