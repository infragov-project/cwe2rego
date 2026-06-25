package glitch

import data.glitch_lib

weak_crypto_terms := {"des", "3des", "rc4", "rc2", "blowfish", "md5", "sha1", "md5_crypt", "sha1_crypt", "des_crypt", "sha", "cbc_sha", "md5_crypt"}

get_line(node) = node.line {
    node.line
} else = 0 {
    true
}

# Walk all nodes recursively
glitch_walk(node) = {n |
    walk(node, [_, n])
}

# Normalize string for comparison
normalize(str) = lower(str)

# Check if string contains any weak crypto term
contains_weak_term(str) {
    norm_str := normalize(str)
    term := weak_crypto_terms[_]
    contains(norm_str, term)
}

# Extract string value from node if it's a String
get_string_value(node) = node.value {
    node.ir_type == "String"
}

# Get all string values from a node recursively
all_string_values(node) = values {
    values := {val |
        n := glitch_walk(node)[_]
        n.ir_type == "String"
        val := n.value
    }
}

# Check if attribute name indicates crypto context
is_crypto_attr_name(name) {
    norm := normalize(name)
    contains(norm, "cipher")
}

is_crypto_attr_name(name) {
    norm := normalize(name)
    contains(norm, "encrypt")
}

is_crypto_attr_name(name) {
    norm := normalize(name)
    contains(norm, "auth_method")
}

is_crypto_attr_name(name) {
    norm := normalize(name)
    contains(norm, "hash")
    not contains(norm, "hashicorp")
    not contains(norm, "hashing")
}

is_crypto_attr_name(name) {
    norm := normalize(name)
    contains(norm, "password")
}

# Check if variable name indicates crypto context
is_crypto_var_name(name) {
    norm := normalize(name)
    contains(norm, "cipher")
}

is_crypto_var_name(name) {
    norm := normalize(name)
    contains(norm, "cipher_suites")
}

is_crypto_var_name(name) {
    norm := normalize(name)
    contains(norm, "password")
}

# Check if access key indicates weak crypto
is_weak_access_key(key) {
    norm := normalize(key)
    contains_weak_term(norm)
}

# Detect weak crypto in Variable nodes (cipher_suites, password, etc.)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    node := glitch_walk(parent)[_]
    node.ir_type == "Variable"
    
    # Check if variable name indicates crypto context
    is_crypto_var_name(node.name)
    
    # Check if any string value contains weak crypto terms
    str_val := get_string_value(node.value)
    contains_weak_term(str_val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": {"ir_type": "Variable", "line": get_line(node), "name": node.name, "value": str_val},
        "path": parent.path,
        "description": "Weak cryptographic configuration - Variable uses weak cipher/encryption algorithm. (CWE-326)"
    }
}

# Detect weak crypto in Attribute nodes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    node := glitch_walk(parent)[_]
    node.ir_type == "Attribute"
    
    # Direct string value check for attributes like auth_method => 'md5'
    node.value.ir_type == "String"
    val_str := node.value.value
    
    # Check if attribute name is crypto-related or value contains weak terms
    (is_crypto_attr_name(node.name); contains_weak_term(val_str))
    
    result := {
        "type": "sec_weak_crypt",
        "element": {"ir_type": "Attribute", "line": get_line(node), "name": node.name, "value": val_str},
        "path": parent.path,
        "description": "Weak cryptographic algorithm in attribute - Avoid using deprecated or weak cryptographic algorithms. (CWE-326)"
    }
}

# Detect weak crypto in Access nodes (like password_md5)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    node := glitch_walk(parent)[_]
    node.ir_type == "Access"
    
    node.right.ir_type == "String"
    right_str := node.right.value
    
    # Check if access key contains weak crypto terms
    contains_weak_term(right_str)
    
    result := {
        "type": "sec_weak_crypt",
        "element": {"ir_type": "Access", "line": get_line(node), "access_key": right_str},
        "path": parent.path,
        "description": "Weak cryptographic reference in variable access - Accessing weak hash/encryption method. (CWE-326)"
    }
}

# Detect weak crypto in Hash entries with encrypt/hash keys
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    node := glitch_walk(parent)[_]
    node.ir_type == "Hash"
    
    entry := node.value[_]
    entry.key.ir_type == "String"
    key_str := entry.key.value
    
    # Check if key indicates encryption/hash context
    is_crypto_attr_name(key_str)
    
    # Get string value from entry
    entry.value.ir_type == "String"
    val_str := entry.value.value
    
    # Check if value contains weak crypto terms
    contains_weak_term(val_str)
    
    result := {
        "type": "sec_weak_crypt",
        "element": {"ir_type": "HashEntry", "line": get_line(entry.value), "key": key_str, "value": val_str},
        "path": parent.path,
        "description": "Weak cryptographic algorithm in hash - Avoid using deprecated or weak cryptographic algorithms. (CWE-326)"
    }
}

# Detect weak crypto in FunctionCall arguments
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    node := glitch_walk(parent)[_]
    node.ir_type == "FunctionCall"
    
    # Check if function name indicates hash/encrypt operations
    func_norm := lower(node.name)
    contains(func_norm, "hash")
    
    # Check arguments for weak crypto terms
    arg := node.args[_]
    arg.ir_type == "String"
    arg_val := arg.value
    
    contains_weak_term(arg_val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": {"ir_type": "FunctionCall", "line": get_line(node), "name": node.name, "arg_value": arg_val},
        "path": parent.path,
        "description": "Weak cryptographic function argument - Avoid using weak hash/encryption algorithms. (CWE-326)"
    }
}

# Detect weak crypto in MethodCall
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    node := glitch_walk(parent)[_]
    node.ir_type == "MethodCall"
    
    # Check if method name indicates hash/encrypt operations
    method_norm := lower(node.method)
    contains(method_norm, "hash")
    
    # Check arguments for weak crypto terms
    arg := node.args[_]
    arg.ir_type == "String"
    arg_val := arg.value
    
    contains_weak_term(arg_val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": {"ir_type": "MethodCall", "line": get_line(node), "method": node.method, "arg_value": arg_val},
        "path": parent.path,
        "description": "Weak cryptographic method argument - Avoid using weak hash/encryption algorithms. (CWE-326)"
    }
}

# General catch-all: any string containing weak crypto terms in crypto context
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    node := glitch_walk(parent)[_]
    node.ir_type == "String"
    str_val := node.value
    
    # Must contain weak crypto term
    contains_weak_term(str_val)
    
    # Must be in some crypto context - check parent containers
    has_crypto_context(node, parent)
    
    result := {
        "type": "sec_weak_crypt",
        "element": {"ir_type": "String", "line": get_line(node), "value": str_val},
        "path": parent.path,
        "description": "Weak cryptographic algorithm value - Avoid using deprecated or weak cryptographic algorithms. (CWE-326)"
    }
}

# Helper to check if a string node is in a crypto context
has_crypto_context(node, root) {
    # Check if parent is an Attribute with crypto name
    p := glitch_walk(root)[_]
    p.ir_type == "Attribute"
    p.value.line == node.line
    p.value.value == node.value
    is_crypto_attr_name(p.name)
} else {
    # Check if parent is a Hash entry with crypto key
    p := glitch_walk(root)[_]
    p.ir_type == "Hash"
    entry := p.value[_]
    entry.value.line == node.line
    entry.value.value == node.value
    is_crypto_attr_name(entry.key.value)
} else {
    # Check if any ancestor has crypto-related name
    p := glitch_walk(root)[_]
    p.ir_type == "Variable"
    p.value.line == node.line
    p.value.value == node.value
    is_crypto_var_name(p.name)
} else {
    # Check if in function/method call with crypto name
    p := glitch_walk(root)[_]
    p.ir_type == "FunctionCall"
    arg := p.args[_]
    arg.line == node.line
    arg.value == node.value
    contains(lower(p.name), "hash")
} else {
    # Check if in Attribute that has encrypt/auth/cipher anywhere in name
    p := glitch_walk(root)[_]
    p.ir_type == "Attribute"
    p.value.line == node.line
    p.value.value == node.value
    contains(lower(p.name), "encrypt")
} else {
    p := glitch_walk(root)[_]
    p.ir_type == "Attribute"
    p.value.line == node.line
    p.value.value == node.value
    contains(lower(p.name), "auth")
} else {
    p := glitch_walk(root)[_]
    p.ir_type == "Attribute"
    p.value.line == node.line
    p.value.value == node.value
    contains(lower(p.name), "cipher")
}