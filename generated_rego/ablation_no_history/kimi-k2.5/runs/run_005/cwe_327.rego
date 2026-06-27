package glitch

import data.glitch_lib

weak_algorithms := {"md4", "md5", "md2", "sha0", "sha1", "sha-1", "sha-0", "ripemd", "ripemd128", "ripemd160", "hmac-md5", "hmac-md4", "hmac-sha1", "des", "3des", "tripledes", "tdea", "blowfish", "rc2", "rc4", "rc4-40", "rc4-hmac", "tea", "xtea", "idea", "dsa", "sslv2", "sslv3", "sslv2.0", "sslv3.0", "tls1.0", "tls1.1", "tls1_0", "tls1_1", "tlsv1.0", "tlsv1.1", "export", "anon", "null", "e_null", "a_null", "low", "dh512", "dh1024"}

crypto_context_fields := {"algorithm", "cipher", "crypto", "encrypt", "hash", "digest", "mac", "tls", "ssl", "cipher_suite", "key_exchange", "signature", "protocol", "version", "ssl_policy", "tls_version", "min_tls_version", "encryption_algorithm", "key_algorithm", "signature_algorithm", "ike_versions", "ipsec_policy"}

weak_crypto_configs := {"enable_legacy_ciphers", "use_deprecated_algorithms", "allow_weak_crypto", "insecure_skip_verify", "allow_legacy_ssl"}

is_standalone_weak_keyword(str) {
    lowered := lower(str)
    algo := weak_algorithms[_]
    regex.match(sprintf("(^|[^a-zA-Z0-9_-])%s($|[^a-zA-Z0-9_-])", [algo]), lowered)
}

extract_string_value(node) = val {
    node.ir_type == "String"
    val := node.value
} else = val {
    node.ir_type == "VariableReference"
    val := node.value
} else = null

has_weak_value(node) {
    str := extract_string_value(node)
    str != null
    is_standalone_weak_keyword(str)
}

has_weak_in_args(args) {
    arg := args[_]
    has_weak_value(arg)
}

find_weak_in_nested(node) = found {
    found := {n |
        walk(node, [_, n])
        has_weak_value(n)
    }
}

is_crypto_context(name) {
    lowered := lower(name)
    field := crypto_context_fields[_]
    contains(lowered, field)
}

is_weak_boolean_flag(name) {
    lowered := lower(name)
    flag := weak_crypto_configs[_]
    contains(lowered, flag)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := {n |
        walk(parent, [_, n])
        n.ir_type == "Attribute"
    }
    attr := attrs[_]
    
    is_crypto_context(attr.name)
    weak_found := find_weak_in_nested(attr.value)
    count(weak_found) > 0
    
    result := {
		"type": "sec_weak_crypt",
		"element": attr,
		"path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Attribute with cryptographic context contains weak algorithm. (CWE-327)"
	}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := {n |
        walk(parent, [_, n])
        n.ir_type == "Variable"
    }
    v := vars[_]
    
    is_crypto_context(v.name)
    weak_found := find_weak_in_nested(v.value)
    count(weak_found) > 0
    
    result := {
		"type": "sec_weak_crypt",
		"element": v,
		"path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Variable with cryptographic context contains weak algorithm. (CWE-327)"
	}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := {n |
        walk(parent, [_, n])
        n.ir_type == "Attribute"
    }
    attr := attrs[_]
    
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    is_weak_boolean_flag(attr.name)
    
    result := {
		"type": "sec_weak_crypt",
		"element": attr,
		"path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak cryptographic security flag enabled. (CWE-327)"
	}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    funcs := {n |
        walk(parent, [_, n])
        n.ir_type == "FunctionCall"
    }
    fc := funcs[_]
    
    lowered := lower(fc.name)
    algo := weak_algorithms[_]
    regex.match(sprintf("(^|[^a-zA-Z0-9_-])%s($|[^a-zA-Z0-9_-])", [algo]), lowered)
    
    result := {
		"type": "sec_weak_crypt",
		"element": fc,
		"path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Function call with weak cryptographic algorithm name. (CWE-327)"
	}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    funcs := {n |
        walk(parent, [_, n])
        n.ir_type == "FunctionCall"
    }
    fc := funcs[_]
    
    has_weak_in_args(fc.args)
    
    result := {
		"type": "sec_weak_crypt",
		"element": fc,
		"path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Function call with weak cryptographic algorithm argument. (CWE-327)"
	}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := {n |
        walk(parent, [_, n])
        n.ir_type == "Attribute"
    }
    attr := attrs[_]
    
    walk(attr.value, [_, n])
    n.ir_type == "Hash"
    entry := n.value[_]
    is_crypto_context(entry.key.value)
    has_weak_value(entry.value)
    
    result := {
		"type": "sec_weak_crypt",
		"element": attr,
		"path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Nested hash with cryptographic context contains weak algorithm. (CWE-327)"
	}
}