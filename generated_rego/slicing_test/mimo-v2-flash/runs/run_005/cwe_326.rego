package glitch

import data.glitch_lib

weak_algorithms := {"des", "3des", "tripledes", "rc4", "md5", "sha1", "md5_crypt", "tls_1_0", "tls_1_1", "ssl_v2", "ssl_v3", "rsa_1024", "aes_128"}

encryption_attributes := {"encrypt", "algorithm", "cipher", "protocol", "version", "key_length", "key_size", "bits", "length", "ssl_policy", "tls_version"}

hashing_functions := {"hash", "md5", "sha1"}

check_weak_algorithm(str) {
    algorithm := weak_algorithms[_]
    regex.match(sprintf("(?i)\\b%s\\b", [algorithm]), str)
}

# Rule 1: Check for weak hashing algorithms in function calls (Ansible)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    
    # Check if function name indicates hashing
    hashing_functions[_] = func_name
    regex.match(sprintf("(?i).*%s.*", [func_name]), node.name)
    
    # Check arguments for weak algorithm
    node.args[_].ir_type == "String"
    algorithm_arg := node.args[_]
    check_weak_algorithm(algorithm_arg.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of weak hashing algorithm in function call (CWE-326)"
    }
}

# Rule 2: Check for weak encryption in nested structures (like Ansible vars_prompt)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    
    # Check if attribute value is an Array (like vars_prompt)
    walk(attr.value, [_, array_node])
    array_node.ir_type == "Array"
    
    # Check each hash in the array
    hash_node := array_node.value[_]
    hash_node.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    pair := hash_node.value[_]
    key := pair.key
    value := pair.value
    
    # Check if the key is an encryption-related key
    key.ir_type == "String"
    encryption_attributes[_] = keyword
    glitch_lib.contains(key.value, keyword)
    
    # Check if the value is a weak algorithm
    value.ir_type == "String"
    check_weak_algorithm(value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm in nested configuration (CWE-326)"
    }
}

# Rule 3: Check for weak encryption in direct attributes (avoid false positives by checking context)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    
    # Only check if the attribute name matches encryption-related keywords
    encryption_attributes[_] = keyword
    glitch_lib.contains(attr.name, keyword)
    
    # Check the attribute value for weak algorithms (only if it's a string)
    walk(attr.value, [_, subnode])
    subnode.ir_type == "String"
    check_weak_algorithm(subnode.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm in attribute (CWE-326)"
    }
}

# Rule 4: Check for insufficient key length in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    
    # Only check if the attribute name matches key length-related keywords
    key_length_keywords := {"key_length", "key_size", "bits", "length"}
    key_length_keywords[_] = keyword
    glitch_lib.contains(attr.name, keyword)
    
    # Check if value is an integer and less than 2048 (for asymmetric) or 128 (for symmetric)
    walk(attr.value, [_, subnode])
    subnode.ir_type == "Integer"
    subnode.value < 2048
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length in encryption configuration (CWE-326)"
    }
}

# Rule 5: Check for weak encryption in variable references (like Chef password_md5)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Access"
    
    # Check if the access is for a password or key that contains weak algorithm
    node.right.ir_type == "String"
    check_weak_algorithm(node.right.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption algorithm in variable access (CWE-326)"
    }
}