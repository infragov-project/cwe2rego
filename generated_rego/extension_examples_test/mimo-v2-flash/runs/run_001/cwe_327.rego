package glitch

import data.glitch_lib
import future.keywords.in

weak_crypto_patterns := [
    "(?i)\\b(des|3des|rc4|md4|md5|sha1|sslv2|sslv3|tls1\\.0|tls1\\.1|ripemd160|crc32)\\b",
    "(?i)\\b(ecb)\\b",
    "(?i)\\b(md5_crypt)\\b"
]

crypto_attributes := {
    "algorithm", "cipher", "encryption_type", "hashing_algorithm",
    "protocol_version", "tls_version", "ssl_version",
    "key_length", "key_size", "key_spec",
    "hash_algorithm", "digest_algorithm", "checksum_algorithm",
    "random_source", "entropy_source", "rng_type",
    "crypto_library", "crypto_provider",
    "certificate_signature_algorithm", "signature_algorithm",
    "pbkdf2_iterations", "scrypt_params", "argon2_params",
    "salt", "static_salt", "encrypt"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "String"
    
    some pattern in weak_crypto_patterns
    regex.match(pattern, node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in crypto_attributes
    
    walk(attr.value, [path, node])
    node.ir_type == "String"
    
    some pattern in weak_crypto_patterns
    regex.match(pattern, node.value)
    
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
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.name in crypto_attributes
    
    walk(var.value, [path, node])
    node.ir_type == "String"
    
    some pattern in weak_crypto_patterns
    regex.match(pattern, node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    
    some pattern in weak_crypto_patterns
    regex.match(pattern, node.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm (CWE-327)"
    }
}