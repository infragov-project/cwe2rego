package glitch

import data.glitch_lib
import future.keywords.in

algorithm_attr_names := {"algorithm", "cipher", "encryption_method", "key_spec", "encrypt"}
key_size_attr_names := {"key_size", "key_length", "bits"}
protocol_attr_names := {"protocol_version", "tls_policy", "min_tls_version"}
weak_algorithms := {"DES", "3DES", "RC4", "AES128", "RSA1024", "SHA1", "MD5", "BLOWFISH", "RC4-SHA", "md5_crypt", "AES_128"}
weak_protocols := {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
weak_key_sizes := {1024, 128, 160}

check_weak_algorithm(value) {
    value.ir_type == "String"
    lower_value := lower(value.value)
    some weak_alg in weak_algorithms
    lower_weak := lower(weak_alg)
    contains(lower_value, lower_weak)
} else {
    value.ir_type == "FunctionCall"
    lower_name := lower(value.name)
    some weak_alg in weak_algorithms
    lower_weak := lower(weak_alg)
    contains(lower_name, lower_weak)
} else {
    value.ir_type == "FunctionCall"
    some arg in value.args
    arg.ir_type == "String"
    lower_arg := lower(arg.value)
    some weak_alg in weak_algorithms
    lower_weak := lower(weak_alg)
    contains(lower_arg, lower_weak)
} else {
    value.ir_type == "Access"
    value.right.ir_type == "String"
    lower_key := lower(value.right.value)
    some weak_alg in weak_algorithms
    lower_weak := lower(weak_alg)
    contains(lower_key, lower_weak)
}

check_cipher_suite(value) {
    value.ir_type == "Array"
    some elem in value.value
    elem.ir_type == "String"
    lower_elem := lower(elem.value)
    some weak_alg in weak_algorithms
    lower_weak := lower(weak_alg)
    contains(lower_elem, lower_weak)
} else {
    value.ir_type == "String"
    cipher_list := split(trim(value.value, "[]"), ",")
    some cipher in cipher_list
    trimmed_cipher := trim(cipher, " ")
    lower_cipher := lower(trimmed_cipher)
    some weak_alg in weak_algorithms
    lower_weak := lower(weak_alg)
    contains(lower_cipher, lower_weak)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attributes := glitch_lib.all_attributes(parent)
    attr := all_attributes[_]
    
    check_weak_algorithm(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm used. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_variables := glitch_lib.all_variables(parent)
    var := all_variables[_]
    
    check_weak_algorithm(var.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm used in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attributes := glitch_lib.all_attributes(parent)
    attr := all_attributes[_]
    
    key_size_attr_names[attr.name]
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Insufficient key size used. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_variables := glitch_lib.all_variables(parent)
    var := all_variables[_]
    
    key_size_attr_names[var.name]
    var.value.ir_type == "Integer"
    var.value.value < 2048
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate encryption strength - Insufficient key size used in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attributes := glitch_lib.all_attributes(parent)
    attr := all_attributes[_]
    
    protocol_attr_names[attr.name]
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    some weak_proto in weak_protocols
    lower_weak := lower(weak_proto)
    lower_value == lower_weak
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Outdated protocol version used. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_variables := glitch_lib.all_variables(parent)
    var := all_variables[_]
    
    protocol_attr_names[var.name]
    var.value.ir_type == "String"
    lower_value := lower(var.value.value)
    some weak_proto in weak_protocols
    lower_weak := lower(weak_proto)
    lower_value == lower_weak
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate encryption strength - Outdated protocol version used in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attributes := glitch_lib.all_attributes(parent)
    attr := all_attributes[_]
    
    attr.name == "cipher_suites"
    check_cipher_suite(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cipher suite used. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_variables := glitch_lib.all_variables(parent)
    var := all_variables[_]
    
    contains(var.name, "cipher_suites")
    check_cipher_suite(var.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cipher suite used in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attributes := glitch_lib.all_attributes(parent)
    attr := all_attributes[_]
    
    attr.name == "rotation_enabled"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Key rotation disabled. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attributes := glitch_lib.all_attributes(parent)
    attr := all_attributes[_]
    
    attr.name == "encryption_enabled"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Encryption disabled. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attributes := glitch_lib.all_attributes(parent)
    attr := all_attributes[_]
    
    attr.name == "server_side_encryption"
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    some weak_alg in weak_algorithms
    lower_weak := lower(weak_alg)
    lower_value == lower_weak
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak encryption algorithm used for server-side encryption. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attributes := glitch_lib.all_attributes(parent)
    attr := all_attributes[_]
    
    attr.value.ir_type == "Hash"
    some key_value in attr.value.value
    key_value.key.ir_type == "String"
    algorithm_attr_names[key_value.key.value]
    key_value.value.ir_type == "String"
    check_weak_algorithm(key_value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": key_value,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm used in nested hash. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_variables := glitch_lib.all_variables(parent)
    var := all_variables[_]
    
    var.value.ir_type == "Hash"
    some key_value in var.value.value
    key_value.key.ir_type == "String"
    algorithm_attr_names[key_value.key.value]
    key_value.value.ir_type == "String"
    check_weak_algorithm(key_value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": key_value,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm used in nested hash in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attributes := glitch_lib.all_attributes(parent)
    attr := all_attributes[_]
    
    attr.value.ir_type == "Array"
    some elem in attr.value.value
    elem.ir_type == "Hash"
    some key_value in elem.value
    key_value.key.ir_type == "String"
    algorithm_attr_names[key_value.key.value]
    key_value.value.ir_type == "String"
    check_weak_algorithm(key_value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": key_value,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm used in nested hash within array. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_variables := glitch_lib.all_variables(parent)
    var := all_variables[_]
    
    var.value.ir_type == "Array"
    some elem in var.value.value
    elem.ir_type == "Hash"
    some key_value in elem.value
    key_value.key.ir_type == "String"
    algorithm_attr_names[key_value.key.value]
    key_value.value.ir_type == "String"
    check_weak_algorithm(key_value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": key_value,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm used in nested hash within array in variable. (CWE-326)"
    }
}