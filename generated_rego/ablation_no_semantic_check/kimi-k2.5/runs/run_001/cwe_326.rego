package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC4", "BLOWFISH", "MD5", "SHA1", "SHA-1", "ECB"}
weak_tls_versions := {"TLSV1.0", "TLSV1.1", "TLS1_0", "TLS1_1", "SSLV2", "SSLV3", "TLS1.0", "TLS1.1"}
weak_key_sizes := {40, 56, 64, 80, 96, 112, 128, 1024}
weak_mode_values := {"ECB", "NONE", "NULL"}

is_weak_algorithm(value) {
    value.ir_type == "String"
    weak_algorithms[upper(value.value)]
}

is_weak_algorithm(value) {
    value.ir_type == "VariableReference"
    weak_algorithms[upper(value.value)]
}

is_weak_tls_version(value) {
    value.ir_type == "String"
    weak_tls_versions[upper(value.value)]
}

is_weak_tls_version(value) {
    value.ir_type == "VariableReference"
    weak_tls_versions[upper(value.value)]
}

is_weak_key_size(value) {
    value.ir_type == "Integer"
    weak_key_sizes[value.value]
}

is_weak_key_size(value) {
    value.ir_type == "String"
    to_number(value.value, n)
    weak_key_sizes[n]
}

contains_encryption_keyword(name) {
    contains(lower(name), "encryption")
}

contains_encryption_keyword(name) {
    contains(lower(name), "cipher")
}

contains_encryption_keyword(name) {
    contains(lower(name), "crypto")
}

contains_encryption_keyword(name) {
    contains(lower(name), "algorithm")
}

contains_tls_keyword(name) {
    contains(lower(name), "tls")
}

contains_tls_keyword(name) {
    contains(lower(name), "ssl")
}

contains_tls_keyword(name) {
    contains(lower(name), "version")
}

contains_key_size_keyword(name) {
    contains(lower(name), "key")
    contains(lower(name), "size")
}

contains_key_size_keyword(name) {
    contains(lower(name), "key")
    contains(lower(name), "length")
}

contains_key_size_keyword(name) {
    contains(lower(name), "key")
    contains(lower(name), "bit")
}

contains_mode_keyword(name) {
    contains(lower(name), "mode")
}

has_weak_value(val) {
    is_weak_algorithm(val)
}

has_weak_value(val) {
    is_weak_tls_version(val)
}

has_weak_value(val) {
    is_weak_key_size(val)
}

has_weak_value(val) {
    val.ir_type == "String"
    weak_mode_values[upper(val.value)]
}

has_encryption_related_weakness(name, val) {
    contains_encryption_keyword(name)
    has_weak_value(val)
}

has_encryption_related_weakness(name, val) {
    contains_tls_keyword(name)
    is_weak_tls_version(val)
}

has_encryption_related_weakness(name, val) {
    contains_key_size_keyword(name)
    is_weak_key_size(val)
}

has_encryption_related_weakness(name, val) {
    contains_mode_keyword(name)
    val.ir_type == "String"
    weak_mode_values[upper(val.value)]
}

is_disabled_encryption(attr_name, attr_value, all_attrs) {
    attr_name == "enabled"
    attr_value.ir_type == "Boolean"
    attr_value.value == false
    some other_attr
    other_attr = all_attrs[_]
    other_attr != attr_name
    contains_encryption_keyword(other_attr)
}

values_contain_weak_encryption(values) {
    some val
    val = values[_]
    val.ir_type == "String"
    weak_algorithms[upper(val.value)]
}

values_contain_weak_encryption(values) {
    some val
    val = values[_]
    val.ir_type == "VariableReference"
    weak_algorithms[upper(val.value)]
}

values_contain_weak_encryption(values) {
    some val
    val = values[_]
    val.ir_type == "String"
    weak_tls_versions[upper(val.value)]
}

values_contain_weak_encryption(values) {
    some val
    val = values[_]
    val.ir_type == "VariableReference"
    weak_tls_versions[upper(val.value)]
}

values_contain_weak_encryption(values) {
    some val
    val = values[_]
    val.ir_type == "Integer"
    weak_key_sizes[val.value]
}

values_contain_weak_encryption(values) {
    some val
    val = values[_]
    val.ir_type == "String"
    to_number(val.value, n)
    weak_key_sizes[n]
}

values_contain_weak_encryption(values) {
    some val
    val = values[_]
    val.ir_type == "String"
    weak_mode_values[upper(val.value)]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    has_encryption_related_weakness(attr.name, attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithms, protocols, or key sizes may compromise data confidentiality. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    node := vars[_]
    
    has_encryption_related_weakness(node.name, node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithms, protocols, or key sizes may compromise data confidentiality. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr_names := {a.name | a := attrs[_]}
    
    is_disabled_encryption(attr.name, attr.value, attr_names)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Encryption is explicitly disabled, which may compromise data confidentiality. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.value.ir_type == "Hash"
    values := {v | v := attr.value.value[_]}
    values_contain_weak_encryption(values)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithms, protocols, or key sizes may compromise data confidentiality. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    node := vars[_]
    
    node.value.ir_type == "Hash"
    values := {v | v := node.value.value[_]}
    values_contain_weak_encryption(values)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithms, protocols, or key sizes may compromise data confidentiality. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.value.ir_type == "Array"
    values := {v | v := attr.value.value[_]}
    values_contain_weak_encryption(values)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithms, protocols, or key sizes may compromise data confidentiality. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    node := vars[_]
    
    node.value.ir_type == "Array"
    values := {v | v := node.value.value[_]}
    values_contain_weak_encryption(values)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithms, protocols, or key sizes may compromise data confidentiality. (CWE-326)"
    }
}