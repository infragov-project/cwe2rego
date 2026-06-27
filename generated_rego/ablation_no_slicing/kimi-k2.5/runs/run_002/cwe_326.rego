package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC2", "RC4", "MD5", "SHA1", "SHA-1", "ECB", "CBC_SHA", "RSA_WITH_AES_128_CBC", "RSA_WITH_AES_256_CBC"}

weak_protocols := {"SSLv2", "SSLv3", "TLS1.0", "TLS1.1", "TLS 1.0", "TLS 1.1", "SSLv2.0", "SSLv3.0"}

encryption_keywords := {"encrypt", "cipher", "ssl", "tls", "hash", "algorithm", "protocol", "key", "mac", "hmac", "signature", "cert", "keystore", "truststore", "auth_method", "auth", "suite", "crypt"}

is_weak_algorithm(val) {
    lower_val := lower(val)
    contains(lower_val, "des")
    contains(lower_val, "3des") == false
}

is_weak_algorithm(val) {
    lower_val := lower(val)
    contains(lower_val, "3des")
}

is_weak_algorithm(val) {
    lower_val := lower(val)
    contains(lower_val, "rc2")
}

is_weak_algorithm(val) {
    lower_val := lower(val)
    contains(lower_val, "rc4")
}

is_weak_algorithm(val) {
    lower_val := lower(val)
    contains(lower_val, "md5")
}

is_weak_algorithm(val) {
    lower_val := lower(val)
    contains(lower_val, "sha1")
}

is_weak_algorithm(val) {
    lower_val := lower(val)
    contains(lower_val, "sha-1")
}

is_weak_algorithm(val) {
    lower_val := lower(val)
    contains(lower_val, "ecb")
}

is_weak_algorithm(val) {
    lower_val := lower(val)
    contains(lower_val, "cbc_sha")
}

is_weak_algorithm(val) {
    lower_val := lower(val)
    contains(lower_val, "rsa_with_aes_128_cbc")
}

is_weak_algorithm(val) {
    lower_val := lower(val)
    contains(lower_val, "rsa_with_aes_256_cbc")
}

is_weak_algorithm(val) {
    lower_val := lower(val)
    regex.match(".*_md5.*", lower_val)
}

is_weak_algorithm(val) {
    lower_val := lower(val)
    regex.match(".*_sha[^0-9].*", lower_val)
    not regex.match(".*_sha[2-9].*", lower_val)
    not regex.match(".*_sha256.*", lower_val)
    not regex.match(".*_sha384.*", lower_val)
    not regex.match(".*_sha512.*", lower_val)
}

is_encryption_related_attr(name) {
    lower_name := lower(name)
    kw := encryption_keywords[_]
    contains(lower_name, kw)
}

is_hash_function(name) {
    lower_name := lower(name)
    contains(lower_name, "hash")
}

is_hash_function(name) {
    lower_name := lower(name)
    regex.match("^(md5|sha1|sha256|sha512|sha384)[^a-z]", lower_name)
}

has_weak_arg(args) {
    arg := args[_]
    arg.ir_type == "String"
    is_weak_algorithm(arg.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "FunctionCall"
    is_hash_function(node.name)
    has_weak_arg(node.args)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm or hash function. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    is_encryption_related_attr(node.name)
    
    walk(node.value, [_, inner])
    inner.ir_type == "String"
    is_weak_algorithm(inner.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm or configuration. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Variable"
    is_encryption_related_attr(node.name)
    
    walk(node.value, [_, inner])
    inner.ir_type == "String"
    is_weak_algorithm(inner.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm or configuration. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "String"
    is_weak_algorithm(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm or hash function. (CWE-326)"
    }
}