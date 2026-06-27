package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "TDES", "RC2", "RC4", "BLOWFISH", "MD5", "SHA1", "SHA-1"}
weak_protocols := {"TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3", "TLS1.0", "TLS1.1", "TLS 1.0", "TLS 1.1"}
block_modes := {"ECB", "CBC"}
encryption_attr_names := {"encrypt", "encryption", "cipher", "crypto", "ssl", "tls", "cipher_suites", "auth_method", "algo", "algorithm", "digest", "hash", "key_derivation", "ssl_mode"}
key_size_fields := {"key_size", "key_length", "key_bits", "rsa_key_size", "key_size_in_bits", "minimum_key_size", "strength", "public_key_length", "private_key_length", "modulus_length"}
protocol_fields := {"protocol", "tls_version", "ssl_version", "min_tls_version", "min_version", "max_tls_version", "max_version"}
salt_size_fields := {"salt_size", "salt_length", "salt_bits", "salt_len"}

contains_weak_algorithm(str) {
    upper_str := upper(str)
    alg := weak_algorithms[_]
    contains(upper_str, alg)
}

contains_weak_protocol(str) {
    upper_str := upper(str)
    proto := weak_protocols[_]
    contains(upper_str, proto)
}

contains_weak_block_mode(str) {
    upper_str := upper(str)
    mode := block_modes[_]
    contains(upper_str, mode)
}

is_weak_encryption_value(str) {
    lower_str := lower(str)
    regex.match("md5.*crypt|sha1.*crypt|des.*crypt|crypt$", lower_str)
}

is_protocol_field(name) {
    lower_name := lower(name)
    field := protocol_fields[_]
    contains(lower_name, field)
}

is_encryption_related_attr(name) {
    lower_name := lower(name)
    attr := encryption_attr_names[_]
    contains(lower_name, attr)
}

is_key_size_attr(name) {
    lower_name := lower(name)
    field := key_size_fields[_]
    contains(lower_name, field)
}

is_salt_size_attr(name) {
    lower_name := lower(name)
    field := salt_size_fields[_]
    contains(lower_name, field)
}

check_string_weak_crypto(val) {
    contains_weak_algorithm(val)
}

check_string_weak_crypto(val) {
    contains_weak_protocol(val)
}

check_string_weak_crypto(val) {
    contains_weak_block_mode(val)
}

check_string_weak_crypto(val) {
    is_weak_encryption_value(val)
}

check_attr_encryption_related(attr) {
    is_encryption_related_attr(attr.name)
    attr.value.ir_type == "String"
    check_string_weak_crypto(attr.value.value)
}

check_attr_encryption_related(attr) {
    is_encryption_related_attr(attr.name)
    attr.value.ir_type == "Array"
    element := attr.value.value[_]
    element.ir_type == "String"
    check_string_weak_crypto(element.value)
}

check_attr_key_size(attr) {
    is_key_size_attr(attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
}

check_attr_salt_size(attr) {
    is_salt_size_attr(attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value < 16
}

check_attr_protocol(attr) {
    is_protocol_field(attr.name)
    attr.value.ir_type == "String"
    contains_weak_protocol(attr.value.value)
}

check_attr_protocol(attr) {
    is_protocol_field(attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value < 12
}

check_hash_pair_value(pair) {
    pair.ir_type == "KeyValue"
    pair.key.ir_type == "String"
    is_protocol_field(pair.key.value)
    pair.value.ir_type == "String"
    contains_weak_protocol(pair.value.value)
}

check_hash_pair_value(pair) {
    pair.ir_type == "KeyValue"
    pair.key.ir_type == "String"
    is_encryption_related_attr(pair.key.value)
    pair.value.ir_type == "String"
    check_string_weak_crypto(pair.value.value)
}

check_hash_pair_value(pair) {
    pair.ir_type == "KeyValue"
    pair.key.ir_type == "String"
    is_key_size_attr(pair.key.value)
    pair.value.ir_type == "Integer"
    pair.value.value < 2048
}

check_hash_pair_value(pair) {
    pair.ir_type == "KeyValue"
    pair.key.ir_type == "String"
    is_salt_size_attr(pair.key.value)
    pair.value.ir_type == "Integer"
    pair.value.value < 16
}

check_hash_pair_value(pair) {
    pair.ir_type == "KeyValue"
    pair.value.ir_type == "Hash"
    inner_pair := pair.value.value[_]
    check_hash_pair_value(inner_pair)
}

check_hash_pair_value(pair) {
    pair.ir_type == "KeyValue"
    pair.value.ir_type == "Array"
    element := pair.value.value[_]
    element.ir_type == "String"
    check_string_weak_crypto(element.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    check_attr_encryption_related(attr)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm or method detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    check_attr_key_size(attr)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Insufficient key size detected (should be >= 2048 bits). (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    check_attr_salt_size(attr)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Insufficient salt size detected (should be >= 16 bytes). (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    check_attr_protocol(attr)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak protocol version detected (TLS 1.0/1.1 or SSL 2/3). (CWE-326)"
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
    pair := attr.value.value[_]
    check_hash_pair_value(pair)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic configuration in nested hash structure. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    check_attr_encryption_related(var)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm or method detected in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    check_attr_key_size(var)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Insufficient key size detected in variable (should be >= 2048 bits). (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    check_attr_salt_size(var)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Insufficient salt size detected in variable (should be >= 16 bytes). (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    check_attr_protocol(var)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak protocol version detected in variable (TLS 1.0/1.1 or SSL 2/3). (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    pair := var.value.value[_]
    check_hash_pair_value(pair)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic configuration in variable hash structure. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    check_string_weak_crypto(node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic string value detected. (CWE-326)"
    }
}