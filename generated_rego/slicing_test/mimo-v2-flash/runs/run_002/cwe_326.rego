package glitch

import data.glitch_lib

# Detects CWE-326: Inadequate Encryption Strength
# Checks for weak algorithms, hashing, and key lengths in attributes and variables

# Weak patterns regex
weak_algorithm_pattern := "(?i)(des|3des|rc4|aes-128|blowfish|cast-128|md5|sha-?1|sha-?224|hmac-?md5|md5_crypt)"

# Helper to check if a string value matches weak patterns
is_weak_value(val) {
    val.ir_type == "String"
    regex.match(weak_algorithm_pattern, val.value)
}

# Helper to check if an array contains weak values
is_weak_array(arr) {
    arr.ir_type == "Array"
    some elem in arr.value
    elem.ir_type == "String"
    regex.match(weak_algorithm_pattern, elem.value)
}

# Helper to check for weak key lengths (RSA < 2048, symmetric < 128)
is_weak_key_length(attr) {
    attr.ir_type == "Attribute"
    attr.name in {"key_length", "key_size", "rsa_bits"}
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
} else {
    attr.ir_type == "Attribute"
    attr.name in {"key_length", "key_size"}
    attr.value.ir_type == "Integer"
    attr.value.value < 128
}

# Rule 1: Detect weak encryption/hashing in attributes (including nested hash values)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all attributes and variables in the parent
    all_attrs := glitch_lib.all_attributes(parent)
    all_vars := glitch_lib.all_variables(parent)
    key_values := array.concat(array.concat([], all_attrs), all_vars)
    
    kv := key_values[_]
    
    # Check direct value
    is_weak_value(kv.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak encryption or hashing algorithm detected. (CWE-326)"
    }
}

# Rule 2: Detect weak encryption/hashing in nested hash structures (e.g., Ansible vars_prompt)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_attrs := glitch_lib.all_attributes(parent)
    all_vars := glitch_lib.all_variables(parent)
    key_values := array.concat(array.concat([], all_attrs), all_vars)
    
    kv := key_values[_]
    
    # Check if value is an array of hashes
    kv.value.ir_type == "Array"
    some hash_elem in kv.value
    hash_elem.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    some pair in hash_elem.value
    pair.value.ir_type == "String"
    regex.match(weak_algorithm_pattern, pair.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak encryption or hashing algorithm in nested structure. (CWE-326)"
    }
}

# Rule 3: Detect weak key lengths
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_attrs := glitch_lib.all_attributes(parent)
    all_vars := glitch_lib.all_variables(parent)
    key_values := array.concat(array.concat([], all_attrs), all_vars)
    
    kv := key_values[_]
    
    is_weak_key_length(kv)
    
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Inadequate encryption strength - Key size too small. (CWE-326)"
    }
}

# Rule 4: Detect weak encryption in function calls (e.g., Ansible filters)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk through all nodes to find function calls
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    
    # Check function name for hash-related functions
    regex.match("(?i).*hash.*", node.name)
    
    # Check arguments for weak algorithms
    some arg in node.args
    arg.ir_type == "String"
    regex.match(weak_algorithm_pattern, arg.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak hashing algorithm in function call. (CWE-326)"
    }
}