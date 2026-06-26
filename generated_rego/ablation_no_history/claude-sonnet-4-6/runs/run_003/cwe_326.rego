package glitch

import data.glitch_lib

algo_attr_names := {"algorithm", "encryption_algorithm", "cipher_algorithm", "hash_algorithm", "key_algorithm", "signing_algorithm", "signature_hash_algorithm", "certificate_algorithm", "integrity_algorithm", "phase1_encryption", "phase2_encryption", "encrypt", "encryption"}

tls_attr_names := {"ssl_policy", "tls_policy", "security_policy", "min_protocol_version", "minimum_tls_version", "minimum_protocol_version", "protocol_version", "enabled_ssl_protocols", "tls_versions"}

cipher_attr_names := {"cipher_suites", "allowed_ciphers", "enabled_ciphers", "cipher", "cipher_suite"}

key_size_attr_names := {"key_size", "key_bits", "key_length", "bit_length", "rsa_bits", "modulus_length", "public_key_size", "ec_bits", "symmetric_key_length"}

weak_algo_pattern := `(?i).*(3des|triple.des|rc2|rc4|rc5|blowfish|md5|sha1|sha-1|sha_1|\bdes\b).*`

weak_tls_pattern := `(?i).*(sslv?2|sslv?3|tlsv?1\.0|tlsv?1\.1|tls_1_0|tls_1_1).*`

weak_cipher_pattern := `(?i).*(rc4|_des_|3des|null_|_null|\banon\b|\bexport\b).*`

name_matches_any(name, attr_set) {
    lower(name) == lower(attr_set[_])
}

name_matches_any(name, attr_set) {
    k := attr_set[_]
    glitch_lib.contains(lower(name), lower(k))
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    name_matches_any(node.name, key_size_attr_names)
    node.value.ir_type == "Integer"
    node.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Key size is below the recommended minimum. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    name_matches_any(node.name, key_size_attr_names)
    node.value.ir_type == "Integer"
    node.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Key size is below the recommended minimum. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    name_matches_any(node.name, algo_attr_names)
    node.value.ir_type == "String"
    regex.match(weak_algo_pattern, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or deprecated encryption algorithm detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    name_matches_any(node.name, algo_attr_names)
    node.value.ir_type == "String"
    regex.match(weak_algo_pattern, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or deprecated encryption algorithm detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    name_matches_any(entry.key.value, algo_attr_names)
    entry.value.ir_type == "String"
    regex.match(weak_algo_pattern, entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.key,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or deprecated encryption algorithm detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "FunctionCall"
    regex.match(`(?i).*(hash|crypt|encrypt|digest|sign).*`, node.value.name)
    arg := node.value.args[_]
    arg.ir_type == "String"
    regex.match(weak_algo_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or deprecated encryption algorithm detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "Access"
    node.value.right.ir_type == "String"
    regex.match(weak_algo_pattern, node.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or deprecated encryption algorithm detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    name_matches_any(node.name, tls_attr_names)
    node.value.ir_type == "String"
    regex.match(weak_tls_pattern, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or deprecated TLS/SSL protocol version detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    name_matches_any(node.name, cipher_attr_names)
    node.value.ir_type == "String"
    regex.match(weak_cipher_pattern, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or deprecated cipher suite detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    name_matches_any(node.name, cipher_attr_names)
    node.value.ir_type == "String"
    regex.match(weak_cipher_pattern, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or deprecated cipher suite detected. (CWE-326)"
    }
}