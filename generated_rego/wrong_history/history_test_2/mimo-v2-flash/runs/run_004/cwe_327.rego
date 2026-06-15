package glitch

import data.glitch_lib

# Define weak cryptographic algorithms and patterns
weak_algorithms := {"des", "3des", "rc4", "md5", "sha1", "sha-1", "ecb", "rsa-1024", "dsa-512", "md5_crypt", "ssl", "sslv2", "sslv3", "tls 1.0", "tls 1.1"}

# Check if a string contains any weak algorithm pattern
contains_weak_algorithm(str) {
    lower_str := lower(str)
    some alg
    weak_algorithms[alg]
    contains(lower_str, alg)
}

# Check Value nodes for weak algorithms
check_value_for_weak_algo(value) {
    value.ir_type == "String"
    contains_weak_algorithm(value.value)
} else {
    value.ir_type == "FunctionCall"
    contains_weak_algorithm(value.name)
} else {
    value.ir_type == "MethodCall"
    contains_weak_algorithm(value.method)
}

# Recursively check Hash values for weak algorithms
check_hash_for_weak_algo(hash_val) {
    some pair
    hash_val.value[pair]
    check_value_for_weak_algo(pair.value)
} else {
    some pair
    hash_val.value[pair]
    pair.value.ir_type == "Hash"
    check_hash_for_weak_algo(pair.value)
}

# Check Array values for weak algorithms
check_array_for_weak_algo(array_val) {
    some elem
    array_val.value[elem]
    check_value_for_weak_algo(elem)
} else {
    some elem
    array_val.value[elem]
    elem.ir_type == "Hash"
    check_hash_for_weak_algo(elem)
}

# Main detection rule for CWE-327
Glitch_Analysis[result] {
    # Gather all parent unit blocks
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check atomic units for weak algorithms
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check attributes within atomic units
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if attribute value contains weak algorithm
    check_value_for_weak_algo(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm (CWE-327)"
    }
}

# Detection rule for variables (Chef style)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables directly in unit blocks
    some var
    parent.variables[var]
    
    # Check if variable value contains weak algorithm
    check_value_for_weak_algo(var.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm (CWE-327)"
    }
}

# Detection rule for complex values (Hash/Array) in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for Hash or Array values that may contain weak algorithms
    attr.value.ir_type == "Hash"
    check_hash_for_weak_algo(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm (CWE-327)"
    }
}

# Detection rule for Arrays containing weak algorithms
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for Array values that may contain weak algorithms
    attr.value.ir_type == "Array"
    check_array_for_weak_algo(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm (CWE-327)"
    }
}