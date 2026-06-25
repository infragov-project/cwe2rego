package glitch

import data.glitch_lib

# Weak cryptographic algorithms and patterns
weak_algorithms := {"DES", "3DES", "RC2", "RC4", "MD2", "MD4", "MD5", "SHA0", "SHA1", "SHA_1", "DSA"}

# Weak hash patterns for function arguments  
weak_hash_args := {"sha1", "md5", "SHA1", "MD5", "sha_1", "md5_crypt", "MD5_CRYPT", "crypt"}

# Weak modes
weak_modes := {"ECB", "ecb"}

# Weak cipher indicators in TLS/SSL cipher suites
weak_cipher_indicators := {"_CBC_SHA", "_RC4_", "_DES_", "_3DES_", "NULL_", "NULL-", "RC4-", "DES-", "3DES-"}

# Disabled encryption values
disabled_encryption := {"none", "disabled", "no", "false", "off", "NONE", "DISABLED", "NO", "FALSE", "OFF"}

# Core crypto-related attribute names - exact matches for strong crypto context
core_crypto_attrs := {"algorithm", "encryption", "encrypt", "cipher", "ssl", "tls", "hash", "digest", "sign", "auth_method", "kex", "mac", "protocol", "spec", "policy", "ciphers", "suite", "password", "auth", "key_spec", "key_specification", "cipher_suite", "kms_key_spec", "block_cipher_mode", "mode_of_operation", "signature_algorithm", "signing_algorithm", "tls_policy", "ssl_policy", "security_policy", "ike_versions", "vpn_protocol", "minimum_protocol_version", "sse_algorithm", "storage_encrypted", "encryption_at_rest", "snapshot_encryption", "ebs_encrypted", "volume_encryption"}

# Variable name patterns indicating crypto usage - only trigger when value contains actual weak algo
crypto_var_patterns := {"password", "hash", "digest", "cipher", "encrypt", "auth", "key", "secret", "cert", "ssl", "tls"}

# Check if string contains weak algorithm (case insensitive)
contains_weak_algorithm(str) {
    alg := weak_algorithms[_]
    regex.match(sprintf(".*\\b%s\\b.*", [lower(alg)]), lower(str))
}

# Check for weak cipher suite patterns
is_weak_cipher_suite(str) {
    pattern := weak_cipher_indicators[_]
    regex.match(pattern, str)
}

# Check for weak mode
is_weak_mode(str) {
    mode := weak_modes[_]
    regex.match(sprintf(".*\\b%s\\b.*", [mode]), lower(str))
}

# Check for disabled encryption
is_disabled_encryption(str) {
    lower(str) == disabled_encryption[_]
}

is_disabled_encryption(val) {
    val.ir_type == "Boolean"
    val.value == false
}

# Check if name is crypto-related
is_crypto_attr_name(name) {
    lower(name) == core_crypto_attrs[_]
}

# Check if variable name suggests crypto context
is_crypto_var_name(name) {
    pattern := crypto_var_patterns[_]
    contains(lower(name), pattern)
}

# Check if string value is weak crypto
is_weak_crypto_string(str) {
    contains_weak_algorithm(str)
}

is_weak_crypto_string(str) {
    is_weak_cipher_suite(str)
}

is_weak_crypto_string(str) {
    is_weak_mode(str)
}

is_weak_crypto_string(str) {
    lower(str) == weak_hash_args[_]
}

# Extract leaf string values from nested structures
leaf_strings(node) = strings {
    strings := {str |
        walk(node, [_, n])
        n.ir_type == "String"
        str := n.value
    }
}

# Check if any string in node is weak crypto
has_weak_crypto_value(node) {
    str := leaf_strings(node)[_]
    is_weak_crypto_string(str)
}

# Check if any string in node indicates disabled encryption
has_disabled_encryption(node) {
    str := leaf_strings(node)[_]
    is_disabled_encryption(str)
}

# === DETECTION RULES ===

# Rule 1: Weak algorithm in crypto-related Attribute
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    
    is_crypto_attr_name(node.name)
    has_weak_crypto_value(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, deprecated, or broken cryptographic algorithms. (CWE-327)"
    }
}

# Rule 2: Disabled encryption in crypto Attribute
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    
    is_crypto_attr_name(node.name)
    has_disabled_encryption(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Encryption explicitly disabled - Encryption should not be disabled. (CWE-327)"
    }
}

# Rule 3: Weak algorithm in crypto-related Variable
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Variable"
    
    is_crypto_var_name(node.name)
    has_weak_crypto_value(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, deprecated, or broken cryptographic algorithms. (CWE-327)"
    }
}

# Rule 4: Variable name directly IS a weak algorithm name (strong signal)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Variable"
    
    lower(node.name) == weak_algorithms[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Variable name indicates use of broken or risky cryptographic algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Variable"
    
    lower(node.name) == weak_hash_args[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Variable name indicates use of broken or risky cryptographic algorithm. (CWE-327)"
    }
}

# Rule 5: FunctionCall with weak hash algorithm as name
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    
    lower(node.name) == weak_hash_args[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm in function call - Avoid using weak, deprecated, or broken cryptographic algorithms. (CWE-327)"
    }
}

# Rule 6: FunctionCall with crypto-related name and weak algorithm argument
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    
    regex.match("(?i)(hash|digest|encrypt|cipher|hmac|md5|sha)", node.name)
    
    arg := node.args[_]
    str := leaf_strings(arg)[_]
    lower(str) == weak_hash_args[_]
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm in function call - Avoid using weak, deprecated, or broken cryptographic algorithms. (CWE-327)"
    }
}

# Rule 7: Hash entry with crypto key and weak value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Hash"
    
    entry := node.value[_]
    entry.key.ir_type == "String"
    
    is_crypto_attr_name(entry.key.value)
    has_weak_crypto_value(entry.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": entry,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Avoid using weak, deprecated, or broken cryptographic algorithms. (CWE-327)"
    }
}

# Rule 8: Hash entry with disabled encryption
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Hash"
    
    entry := node.value[_]
    entry.key.ir_type == "String"
    
    is_crypto_attr_name(entry.key.value)
    has_disabled_encryption(entry.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": entry,
        "path": parent.path,
        "description": "Encryption explicitly disabled - Encryption should not be disabled. (CWE-327)"
    }
}

# Rule 9: Access to field with name containing weak algorithm
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Access"
    node.right.ir_type == "String"
    
    field := node.right.value
    
    alg := weak_algorithms[_]
    regex.match(sprintf(".*[_]?%s[_]?.*", [lower(alg)]), lower(field))
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Access to cryptographic data using broken algorithm - Avoid using weak, deprecated, or broken cryptographic algorithms. (CWE-327)"
    }
}