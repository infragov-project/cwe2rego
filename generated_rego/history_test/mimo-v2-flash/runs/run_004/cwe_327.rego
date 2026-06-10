package glitch

import data.glitch_lib

# Define patterns for deprecated cryptographic algorithms
deprecated_algorithms := {
    "DES", "3DES", "RC4", "Blowfish", "IDEA",
    "MD2", "MD4", "MD5", "SHA1",
    "XOR", "Base64", "ROT13", "ROT25", "URL Encoding",
    "ECB", "CBC",
    "SSLv2", "SSLv3", "TLS1.0", "TLS1.1"
}

# Check if a string contains any deprecated algorithm
contains_deprecated_algorithm(str) {
    contains(str, deprecated_algorithms[_])
}

# Check if a value node contains deprecated algorithms
check_value_for_deprecated_algorithms(value) {
    value.ir_type == "String"
    contains_deprecated_algorithm(value.value)
} else {
    value.ir_type == "Hash"
    check_hash_for_deprecated_algorithms(value.value)
} else {
    value.ir_type == "Array"
    check_array_for_deprecated_algorithms(value.value)
}

# Recursively check hash values
check_hash_for_deprecated_algorithms(hash) {
    some key, val
    hash[key]
    val.ir_type == "String"
    contains_deprecated_algorithm(val.value)
} else {
    some key, val
    hash[key]
    val.ir_type == "Hash"
    check_hash_for_deprecated_algorithms(val.value)
} else {
    some key, val
    hash[key]
    val.ir_type == "Array"
    check_array_for_deprecated_algorithms(val.value)
}

# Recursively check array values
check_array_for_deprecated_algorithms(arr) {
    some val
    val = arr[_]
    val.ir_type == "String"
    contains_deprecated_algorithm(val.value)
} else {
    some val
    val = arr[_]
    val.ir_type == "Hash"
    check_hash_for_deprecated_algorithms(val.value)
} else {
    some val
    val = arr[_]
    val.ir_type == "Array"
    check_array_for_deprecated_algorithms(val.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all attributes in the parent
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    check_value_for_deprecated_algorithms(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm detected in attribute. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all variables in the parent
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    check_value_for_deprecated_algorithms(var.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm detected in variable. (CWE-327)"
    }
}