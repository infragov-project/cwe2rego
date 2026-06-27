package glitch

import data.glitch_lib

# Weak cryptographic algorithms and hash functions
weak_crypto_algorithms := {
    "des", "3des", "tripledes", "rc2", "rc4", "rc5", "rc6",
    "md5", "md5_crypt", "sha1", "sha-1",
    "blowfish", "idea", "skipjack", "tea", "xtea",
    "aes-128", "aes128", "aes_128",
    "rsa_with_aes_128",
    "with_rc4_128", "with_des", "with_3des",
    "md5-crypt", "sha-1", "sha1-", "-md5", "-sha1"
}

# Crypto-related attribute/variable names
crypto_names := {
    "encrypt", "encryption", "cipher", "ciphers", "cipher_suites",
    "hash", "algorithm", "crypto", "check_method", "checksum",
    "digest", "mac", "key_type", "key_spec", "sig_algorithm",
    "kdf", "pbkdf", "auth_method", "verify_method", "password"
}

# Patterns that are definitely NOT crypto contexts (to reduce false positives)
excluded_context_patterns := {
    "openssl enc -aes-256", "openssl enc -aes-128-gcm", "openssl aes",
    "-salt", "sha256", "sha-256", "sha512", "sha-384", "aes-256", "aes256",
    "zabbix_extra_conf", "*.conf", "conf.d",
    "httpd_conf", "nginx_conf", "log_conf", "cfg", "config"
}

# Check if string contains weak crypto algorithm as a standalone word/token
has_weak_crypto_token(value_str) {
    lower_val := lower(value_str)
    algo := weak_crypto_algorithms[_]
    token_patterns := [
        sprintf("(^|[^a-z0-9_-])%s($|[^a-z0-9_-])", [algo]),
        sprintf("^%s$", [algo]),
        sprintf("^%s[_-]", [algo]),
        sprintf("[_-]%s$", [algo]),
        sprintf("[_-]%s[_-]", [algo])
    ]
    pattern := token_patterns[_]
    regex.match(pattern, lower_val)
}

# Check if this is a properly excluded context (strong crypto usage)
is_excluded_context(value_str) {
    lower_val := lower(value_str)
    pattern := excluded_context_patterns[_]
    regex.match(pattern, lower_val)
}

# Check if name is crypto-related
is_crypto_name(name) {
    lower_name := lower(name)
    pattern := crypto_names[_]
    contains(lower_name, pattern)
}

contains(str, substr) {
    lower_str := lower(str)
    lower_sub := lower(substr)
    pattern := sprintf(".*%s.*", [lower_sub])
    regex.match(pattern, lower_str)
}

# Get all strings from a node recursively, including Access right-hand sides
all_strings(node) = strings {
    strings = {n |
        walk(node, [_, n])
        n.ir_type == "String"
    } | {n |
        walk(node, [_, access])
        access.ir_type == "Access"
        access.right.ir_type == "String"
        n := access.right
    } | {n |
        walk(node, [_, access])
        access.ir_type == "Access"
        access.left.ir_type == "String"
        n := access.left
    }
}

# Get all string values where weak crypto might appear (including identifiers in Access nodes)
all_identifier_strings(node) = strings {
    strings = {s.value |
        walk(node, [_, n])
        n.ir_type == "String"
        s := n
    } | {s.value |
        walk(node, [_, access])
        access.ir_type == "Access"
        access.right.ir_type == "String"
        s := access.right
    } | {n.name |
        walk(node, [_, n])
        n.ir_type == "Attribute"
    } | {n.name |
        walk(node, [_, n])
        n.ir_type == "Variable"
    }
}

# Check node has weak crypto (with context exclusion) - checks all string values
node_has_weak_crypto(node) {
    val := all_identifier_strings(node)[_]
    has_weak_crypto_token(val)
    not is_excluded_context(val)
}

# Check if an Access node itself contains weak crypto in its key/identifier
access_has_weak_crypto(access_node) {
    access_node.ir_type == "Access"
    access_node.right.ir_type == "String"
    has_weak_crypto_token(access_node.right.value)
}

# Detection in Attribute values where attribute name suggests crypto context
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    is_crypto_name(attr.name)
    node_has_weak_crypto(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in cryptographic context. Use AES-256 or equivalent strong encryption. (CWE-326)"
    }
}

# Detection in Attribute where the value is an Access node with weak crypto key
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    is_crypto_name(attr.name)
    attr.value.ir_type == "Access"
    access_has_weak_crypto(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in Access key. Use AES-256 or equivalent strong encryption. (CWE-326)"
    }
}

# Detection in Variable assignments where variable name suggests crypto
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, var])
    var.ir_type == "Variable"
    is_crypto_name(var.name)
    node_has_weak_crypto(var.value)

    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in variable with crypto-related name. Use AES-256 or equivalent strong encryption. (CWE-326)"
    }
}

# Detection in FunctionCall with crypto-related function names
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, fc])
    fc.ir_type == "FunctionCall"
    
    fc_name_lower := lower(fc.name)
    regex.match(".*(md5|sha1|des|rc4|blowfish).*", fc_name_lower)
    
    result := {
        "type": "sec_weak_crypt",
        "element": fc,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic function call. Use algorithms considered strong by current standards. (CWE-326)"
    }
}

# Detection in FunctionCall arguments that are weak crypto algorithm names
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, fc])
    fc.ir_type == "FunctionCall"
    arg := fc.args[_]
    arg.ir_type == "String"
    has_weak_crypto_token(arg.value)
    not is_excluded_context(arg.value)

    result := {
        "type": "sec_weak_crypt",
        "element": fc,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in function argument. Use algorithms considered strong by current standards. (CWE-326)"
    }
}

# Detection in Hash keys and values for crypto-config structures
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, h])
    h.ir_type == "Hash"
    
    pair := h.value[_]
    pair.key.ir_type == "String"
    is_crypto_name(pair.key.value)
    pair.value.ir_type == "String"
    has_weak_crypto_token(pair.value.value)
    not is_excluded_context(pair.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": pair.key,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in configuration. Use AES-256 or equivalent strong encryption. (CWE-326)"
    }
}

# Detection: any Access node that uses weak crypto algorithm as its key (e.g., data['password_md5'])
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, access])
    access.ir_type == "Access"
    access.right.ir_type == "String"
    has_weak_crypto_token(access.right.value)
    not is_excluded_context(access.right.value)

    result := {
        "type": "sec_weak_crypt",
        "element": access,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in data access key. Use algorithms considered strong by current standards. (CWE-326)"
    }
}

# Detection: variables or attributes whose names contain weak crypto (e.g., password_md5)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "Variable"
    has_weak_crypto_token(node.name)
    not is_excluded_context(node.name)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in variable name. Use AES-256 or equivalent strong encryption. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "Attribute"
    has_weak_crypto_token(node.name)
    not is_excluded_context(node.name)

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in attribute name. Use AES-256 or equivalent strong encryption. (CWE-326)"
    }
}