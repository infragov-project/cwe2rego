package glitch

import data.glitch_lib

# Weak cryptographic algorithms and related patterns
weak_algorithms = {"DES", "des", "3DES", "3des", "RC2", "rc2", "RC4", "rc4", "IDEA", "idea", "Blowfish", "blowfish", "MD5", "md5", "SHA1", "sha1", "SHA-1", "sha-1", "SHA", "sha"}

# Weak TLS/SSL versions
weak_tls_versions = {"TLSv1.0", "tlsv1.0", "TLSv1.1", "tlsv1.1", "SSLv2", "sslv2", "SSLv3", "sslv3", "1.0", "1.1"}

# Context patterns that indicate cryptographic usage
crypto_context_patterns = {"password", "key", "cert", "cipher", "algorithm", "hash", "encrypt", "auth", "ssl", "tls", "crypto", "secret", "suite", "md5", "sha"}

# Strong algorithms that should not be flagged
strong_algorithms = {"SunX509", "JKS", "AES", "AES256", "AES128", "SHA256", "SHA-384", "SHA-512", "RSA", "ECDSA", "SHA3", "SHA256withRSA"}

# Safe patterns that shouldn't be flagged
safe_patterns = {"uuid", "Order", "version", "file", "path", "log", "run"}

# Gather all blocks including nested ones
all_blocks[blk] {
    blk := glitch_lib._gather_parent_unit_blocks[_]
}

all_blocks[blk] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    walk(parent, [_, nested])
    nested.ir_type == "UnitBlock"
    blk := nested
}

# Case-insensitive string containment
contains_ci(str, substr) {
    regex.match(sprintf("(?i)%s", [substr]), str)
}

# Check if string matches weak algorithm
is_weak_algo(str) {
    alg := weak_algorithms[_]
    contains_ci(str, alg)
    not is_strong_algo(str)
}

# Check if string has crypto context
has_crypto_context(str) {
    pattern := crypto_context_patterns[_]
    contains_ci(str, pattern)
}

is_strong_algo(str) {
    alg := strong_algorithms[_]
    lower(str) == lower(alg)
}

lower(str) = result {
    result := str
    is_string(str)
}

# Check for safe patterns
contains_safe_pattern(str) {
    pattern := safe_patterns[_]
    contains_ci(str, pattern)
}

# Check if value is a string with weak algorithm
check_value_for_weak_algo(val) {
    val.ir_type == "String"
    is_weak_algo(val.value)
    not contains_safe_pattern(val.value)
}

get_string(val) = val.value {
    val.ir_type == "String"
}

get_string(val) = val.value {
    val.ir_type == "VariableReference"
}

# Detect weak crypto in Variable names (Chef attribute-style names like default[...]['cipher_suites'])
Glitch_Analysis[result] {
    parent := all_blocks[_]
    parent.path != ""
    
    walk(parent, [path, n])
    n.ir_type == "Variable"
    
    # Check if variable name contains crypto context AND weak algorithm
    has_crypto_context(n.name)
    is_weak_algo(n.name)
    not contains_safe_pattern(n.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Variable name contains weak cryptographic indicator. (CWE-326)"
    }
}

# Detect weak crypto in string values with crypto context in their structure
Glitch_Analysis[result] {
    parent := all_blocks[_]
    parent.path != ""
    
    walk(parent, [_, n])
    n.ir_type == "String"
    
    str_val := n.value
    
    # Check for weak cipher patterns like _CBC_SHA
    regex.match(".*_CBC_SHA[^0-9].*", str_val)
    not contains_safe_pattern(str_val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher suite with SHA-1. (CWE-326)"
    }
}

# Detect weak crypto in any string value with crypto context nearby
Glitch_Analysis[result] {
    parent := all_blocks[_]
    parent.path != ""
    
    walk(parent, [path, n])
    n.ir_type == "String"
    
    str_val := n.value
    is_weak_algo(str_val)
    not contains_safe_pattern(str_val)
    
    # Check if any path element indicates crypto context
    path_elem := path[_]
    path_elem.ir_type == "Attribute"
    has_crypto_context(path_elem.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in crypto context. (CWE-326)"
    }
}

# Detect weak crypto in Variable values
Glitch_Analysis[result] {
    parent := all_blocks[_]
    parent.path != ""
    
    walk(parent, [_, n])
    n.ir_type == "Variable"
    
    # Check if variable name has crypto context
    has_crypto_context(n.name)
    
    # Check value
    val_str := get_string(n.value)
    val_str != null
    is_weak_algo(val_str)
    not contains_safe_pattern(val_str)
    
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in variable value. (CWE-326)"
    }
}

# Detect weak crypto in Access right side (like ['password_md5'])
Glitch_Analysis[result] {
    parent := all_blocks[_]
    parent.path != ""
    
    walk(parent, [_, n])
    n.ir_type == "Access"
    
    right_str := get_string(n.right)
    right_str != null
    
    # Check if the access string itself indicates weak crypto
    is_weak_algo(right_str)
    not contains_safe_pattern(right_str)
    
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in data access key. (CWE-326)"
    }
}

# Detect weak crypto in Access right side with crypto context in left
Glitch_Analysis[result] {
    parent := all_blocks[_]
    parent.path != ""
    
    walk(parent, [_, n])
    n.ir_type == "Access"
    
    right_str := get_string(n.right)
    right_str != null
    is_weak_algo(right_str)
    not contains_safe_pattern(right_str)
    
    # Check left side for crypto context
    left := n.left
    left.ir_type == "VariableReference"
    has_crypto_context(left.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in data access. (CWE-326)"
    }
}

# Check Attribute values
Glitch_Analysis[result] {
    parent := all_blocks[_]
    parent.path != ""
    
    walk(parent, [_, n])
    n.ir_type == "Attribute"
    
    val_str := get_string(n.value)
    val_str != null
    is_weak_algo(val_str)
    not contains_safe_pattern(val_str)
    
    # Check name or value for crypto context
    has_crypto_context(n.name)
}

Glitch_Analysis[result] {
    parent := all_blocks[_]
    parent.path != ""
    
    walk(parent, [_, n])
    n.ir_type == "Attribute"
    
    val_str := get_string(n.value)
    val_str != null
    is_weak_algo(val_str)
    not contains_safe_pattern(val_str)
    
    # Check name or value for crypto context
    has_crypto_context(val_str)
    
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in attribute. (CWE-326)"
    }
}

# Check Hash values
Glitch_Analysis[result] {
    parent := all_blocks[_]
    parent.path != ""
    
    walk(parent, [_, n])
    n.ir_type == "Hash"
    
    kv := n.value[_]
    
    key_str := get_string(kv.key)
    val_str := get_string(kv.value)
    val_str != null
    
    is_weak_algo(val_str)
    not contains_safe_pattern(val_str)
    
    # Check key for crypto context
    key_str != null
    has_crypto_context(key_str)
    
    result := {
        "type": "sec_weak_crypt",
        "element": kv.value,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in hash value. (CWE-326)"
    }
}

# Check function arguments for weak algorithms
Glitch_Analysis[result] {
    parent := all_blocks[_]
    parent.path != ""
    
    walk(parent, [_, n])
    n.ir_type == "FunctionCall"
    
    arg := n.args[_]
    arg_str := get_string(arg)
    arg_str != null
    
    is_weak_algo(arg_str)
    not contains_safe_pattern(arg_str)
    
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in function call argument. (CWE-326)"
    }
}

# Check for weak TLS versions
Glitch_Analysis[result] {
    parent := all_blocks[_]
    parent.path != ""
    
    walk(parent, [_, n])
    n.ir_type == "Attribute"
    
    contains_ci(n.name, "version")
    contains_ci(n.name, "tls")
    
    val_str := get_string(n.value)
    val_str != null
    
    weak_ver := weak_tls_versions[_]
    contains_ci(val_str, weak_ver)
    
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak TLS/SSL version configuration. (CWE-326)"
    }
}

# Check for md5/sha1 function calls
Glitch_Analysis[result] {
    parent := all_blocks[_]
    parent.path != ""
    
    walk(parent, [_, n])
    n.ir_type == "FunctionCall"
    
    name_lower := lower(n.name)
    regex.match("^(md5|sha1|.*\\|md5|.*\\|sha1)$", name_lower)
    
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak hash function. (CWE-326)"
    }
}