package glitch

import data.glitch_lib

weak_hash_pattern := "(?i)sha1|md5|md4|md2"
weak_encryption_pattern := "(?i)des|3des|rc4|md5_crypt|md5"
weak_cipher_pattern := "(?i)rsa_with_aes_128_cbc_sha|rsa_with_aes_256_cbc_sha|tls_rsa_with_aes_128_cbc_sha|tls_rsa_with_aes_256_cbc_sha"

crypto_keywords := {"encrypt", "cipher", "hash", "algorithm", "protocol", "ssl", "tls", "key", "cipher_suites", "ciphers"}

check_weak_crypto_value(value) {
    value.ir_type == "String"
    regex.match(weak_hash_pattern, value.value)
} else {
    value.ir_type == "String"
    regex.match(weak_encryption_pattern, value.value)
} else {
    value.ir_type == "String"
    regex.match(weak_cipher_pattern, value.value)
}

is_crypto_related(name) {
    crypto_keywords[_] = keyword
    regex.match(sprintf("(?i).*%s.*", [keyword]), name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes for weak crypto
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    is_crypto_related(attr.name)
    check_weak_crypto_value(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption strength detected - Use of weak cryptographic algorithms, hashes, or cipher suites. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables for weak crypto
    all_vars := glitch_lib.all_variables(parent)
    var := all_vars[_]
    is_crypto_related(var.name)
    check_weak_crypto_value(var.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Weak encryption strength detected - Use of weak cryptographic algorithms, hashes, or cipher suites. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check function calls for weak hash functions
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    regex.match("(?i)hash", node.name)
    count(node.args) > 0
    arg := node.args[_]
    check_weak_crypto_value(arg)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak hash function detected - Use of cryptographically weak hash algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for weak cipher suites in array values (like in Chef)
    walk(parent, [path, node])
    node.ir_type == "String"
    regex.match(weak_cipher_pattern, node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cipher suite detected - Use of weak cryptographic cipher suites. (CWE-326)"
    }
}