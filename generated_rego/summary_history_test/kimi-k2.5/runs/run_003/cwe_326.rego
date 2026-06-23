package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC4", "RC2", "BLOWFISH", "MD5", "SHA1", "NULL", "MD5_CRYPT", "SHA", "SHA-1", "MD4", "MD5CRYPT", "MD5_CRYPT"}

weak_protocols := {"TLSV1.0", "TLSV1.1", "SSLV3", "SSLV2", "TLS1.0", "TLS1.1", "SSL3", "SSL2", "TLSV1", "SSLV23", "TLSV1_0", "TLSV1_1"}

algorithm_fields := {"encryption_algorithm", "cipher", "cipher_suite", "cipher_suites", "kms_key_spec", "encryption_key", "data_key_spec", "sse_algorithm", "crypto_key", "key_algorithm", "signature_algorithm", "encrypt", "encryption", "hash", "checksum", "digest", "algorithm", "auth_method"}

key_size_fields := {"key_size", "key_length", "key_bits", "bits", "size", "key_spec", "public_key_bytes", "minimum_key_size", "rsa_key_size", "ec_key_size", "salt_size"}

protocol_fields := {"tls_version", "ssl_protocol", "min_tls_version", "protocol_version", "security_policy", "policy_version", "version", "ssl", "protocol"}

check_weak_algorithm_string(s) {
    some wa
    weak_algorithms[wa]
    upper(s) == wa
}

check_weak_protocol_string(s) {
    some wp
    weak_protocols[wp]
    upper(s) == wp
}

string_contains_weak_algo(s) {
    regex.match(`(?i)(md5|sha1|des|3des|rc4|rc2|blowfish|null|anon|md5_crypt|md5crypt)`, s)
}

string_contains_weak_cipher(s) {
    regex.match(`(?i)CBC`, s)
}

string_contains_weak_protocol(s) {
    regex.match(`(?i)(tlsv?1\.0|tlsv?1\.1|sslv?2|sslv?3)`, s)
}

check_string_for_weak_crypto(s) {
    check_weak_algorithm_string(s)
} else {
    string_contains_weak_algo(s)
} else {
    check_weak_protocol_string(s)
} else {
    string_contains_weak_protocol(s)
} else {
    string_contains_weak_cipher(s)
}

is_crypto_related_name(name) {
    some af
    algorithm_fields[af]
    upper(name) == af
} else {
    some pf
    protocol_fields[pf]
    upper(name) == pf
} else {
    some kf
    key_size_fields[kf]
    upper(name) == kf
} else {
    regex.match(`(?i)(md5|sha|des|crypt|encrypt|cipher|ssl|tls|hash|auth|password)`, name)
}

is_key_size_field(name) {
    some kf
    key_size_fields[kf]
    upper(name) == kf
}

match_weak_in_access_right(access_node) {
    access_node.ir_type == "Access"
    access_node.right.ir_type == "String"
    str_val := access_node.right.value
    string_contains_weak_algo(str_val)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some p1, node
    walk(parent, [p1, node])
    node.ir_type == "Attribute"
    attr_name := node.name
    is_key_size_field(attr_name)
    
    some p2, val
    walk(node, [p2, val])
    val.ir_type == "Integer"
    val.value < 128
    val.value > 0
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Insufficient key size detected. Use at least 128 bits for symmetric keys. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some p1, node
    walk(parent, [p1, node])
    match_weak_in_access_right(node)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm referenced in access expression. Use modern encryption standards. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some p1, node
    walk(parent, [p1, node])
    node.ir_type == "Attribute"
    match_weak_in_access_right(node.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm referenced in attribute value. Use modern encryption standards. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some p1, node
    walk(parent, [p1, node])
    node.ir_type == "FunctionCall"
    func_name := node.name
    upper(func_name) == "MD5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic hash function md5 called. Use modern encryption standards. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some p1, node
    walk(parent, [p1, node])
    node.ir_type == "FunctionCall"
    
    some p2, arg
    walk(node, [p2, arg])
    arg.ir_type == "String"
    check_weak_algorithm_string(arg.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in function call argument. Use modern encryption standards. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some p1, node
    walk(parent, [p1, node])
    node.ir_type == "Attribute"
    attr_name := node.name
    
    is_crypto_related_name(attr_name)
    not is_key_size_field(attr_name)
    
    some p2, val
    walk(node, [p2, val])
    val.ir_type == "String"
    str_val := val.value
    check_string_for_weak_crypto(str_val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic configuration detected. Use modern encryption standards. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some p1, node
    walk(parent, [p1, node])
    node.ir_type == "Variable"
    var_name := node.name
    is_crypto_related_name(var_name)
    
    some p2, val
    walk(node.value, [p2, val])
    val.ir_type == "String"
    check_string_for_weak_crypto(val.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic value in variable. Use modern encryption standards. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some p1, node
    walk(parent, [p1, node])
    node.ir_type == "Variable"
    var_name := node.name
    regex.match(`(?i)md5`, var_name)
    
    some p2, val
    walk(node.value, [p2, val])
    val.ir_type == "FunctionCall"
    upper(val.name) == "MD5"
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Variable with md5 in name assigned from md5() call. Use modern encryption standards. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some p1, node
    walk(parent, [p1, node])
    node.ir_type == "Hash"
    
    some entry
    val := node.value[entry]
    val.key.ir_type == "String"
    key_name := val.key.value
    is_crypto_related_name(key_name)
    
    val.value.ir_type == "String"
    check_string_for_weak_crypto(val.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": val.value,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic value in hash entry. Use modern encryption standards. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some p1, node
    walk(parent, [p1, node])
    node.ir_type == "Array"
    
    some p2, elem
    walk(node, [p2, elem])
    elem.ir_type == "Hash"
    
    some entry
    val := elem.value[entry]
    val.key.ir_type == "String"
    key_name := val.key.value
    is_crypto_related_name(key_name)
    
    val.value.ir_type == "String"
    check_string_for_weak_crypto(val.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": val.value,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic value in nested hash array. Use modern encryption standards. (CWE-326)"
    }
}