package glitch

import data.glitch_lib

weak_hashing_algorithms := {"MD5", "SHA1", "md5", "sha1"}
weak_encryption_algorithms := {"DES", "3DES", "RC4", "AES-128", "AES_128", "ECB", "RSA-1024"}
weak_protocols := {"SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "TLS1.0", "TLS1.1"}
weak_modes := {"ECB"}
hardcoded_secret_attributes := {"secret", "password", "api_key", "token", "encrypt"}
encryption_keywords := {"algorithm", "cipher", "encryption_algorithm", "kms_key_id", "storage_encryption", "cipher_suites", "cipher_suite"}
hashing_keywords := {"hash_algorithm", "digest", "signature_algorithm", "password_hashing", "hash"}
protocol_keywords := {"ssl_version", "tls_version", "protocol", "security_policy"}
mode_keywords := {"mode", "block_mode", "cipher_mode"}
library_keywords := {"crypto_library", "provider", "module_version", "ssl_version", "tls_version"}
key_size_keywords := {"key_size", "key_length", "salt_size"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    glitch_lib.traverse(attr.value, weak_hashing_algorithms)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky hashing algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    walk(node, [path, n])
    n.ir_type == "FunctionCall"
    n.name == "filter|hash"
    count(n.args) > 1
    arg := n.args[1]
    arg.ir_type == "String"
    weak_hashing_algorithms contains arg.value
    
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of broken or risky hashing algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    glitch_lib.traverse(attr.value, weak_encryption_algorithms)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    protocol_keywords contains attr.name
    glitch_lib.traverse(attr.value, weak_protocols)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak cryptographic protocol version (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    mode_keywords contains attr.name
    glitch_lib.traverse(attr.value, weak_modes)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of insecure cryptographic mode (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    key_size_keywords contains attr.name
    attr.value.ir_type == "Integer"
    attr.value.value < 256
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Outdated key management setting: key size too small (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    hardcoded_secret_attributes contains attr.name
    attr.value.ir_type == "String"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded or plaintext secret (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    hardcoded_secret_attributes contains attr.name
    attr.value.ir_type == "VariableReference"
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded or plaintext secret (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    library_keywords contains attr.name
    attr.value.ir_type == "String"
    regex.match("(?i)(openssl|libressl|boringssl).*version.*((0\\.[0-9])|(1\\.[0-0])|(1\\.[0-1]\\.[0-0]))", attr.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Non-compliant cryptographic library (CWE-327)"
    }
}