package glitch

import data.glitch_lib

weak_algo_fields := {"algorithm", "encryption_algorithm", "cipher", "cipher_suite", "crypto_algorithm", "hash_algorithm", "digest_algorithm", "signing_algorithm", "integrity_algorithm", "key_algorithm", "signature_algorithm", "server_side_encryption", "sse_algorithm", "phase1_encryption", "phase2_encryption", "ike_encryption_algorithm", "esp_encryption_algorithm", "encrypt", "authentication_method", "encryption_method", "checksum_algorithm", "auth_method"}

tls_proto_fields := {"ssl_policy", "tls_version", "minimum_tls_version", "min_protocol_version", "security_policy", "ssl_protocol"}

key_size_fields := {"key_size", "key_length", "rsa_bits", "key_bits", "modulus_length", "ec_bits"}

cipher_suite_fields := {"cipher_suites", "allowed_ciphers", "ssl_ciphers", "cipher_list"}

dh_group_fields := {"dh_group", "pfs_group"}

weak_algo_pattern := "(?i).*(md5|md4|sha[-_]?1([^0-9]|$)|3des|triple.?des|rc2|rc4|rc5|blowfish|ecb|crc32|ripemd).*"

weak_tls_pattern := "(?i).*(sslv2|sslv3|ssl2|ssl3|tlsv1\\.0|tlsv1\\.1|tls_1_0|tls_1_1).*"

weak_cipher_pattern := "(?i).*(null|export|anon|rc4|_des_|_3des_|_md5|_sha([^0-9]|$)).*"

name_has_field(name, fields) {
    field := fields[_]
    glitch_lib.contains(name, field)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    name_has_field(attr.name, weak_algo_fields)
    walk(attr.value, [_, str_node])
    str_node.ir_type == "String"
    regex.match(weak_algo_pattern, str_node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak or deprecated encryption algorithm configured. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    name_has_field(v.name, weak_algo_fields)
    walk(v.value, [_, str_node])
    str_node.ir_type == "String"
    regex.match(weak_algo_pattern, str_node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak or deprecated encryption algorithm configured. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    name_has_field(entry.key.value, weak_algo_fields)
    entry.value.ir_type == "String"
    regex.match(weak_algo_pattern, entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.key,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak encryption algorithm in nested configuration. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    walk(v.value, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    name_has_field(entry.key.value, weak_algo_fields)
    entry.value.ir_type == "String"
    regex.match(weak_algo_pattern, entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.key,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak encryption algorithm in nested configuration. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    name_has_field(attr.name, cipher_suite_fields)
    walk(attr.value, [_, str_node])
    str_node.ir_type == "String"
    regex.match(weak_cipher_pattern, str_node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher suite configuration detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    name_has_field(v.name, cipher_suite_fields)
    walk(v.value, [_, str_node])
    str_node.ir_type == "String"
    regex.match(weak_cipher_pattern, str_node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher suite configuration detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    name_has_field(attr.name, tls_proto_fields)
    walk(attr.value, [_, str_node])
    str_node.ir_type == "String"
    regex.match(weak_tls_pattern, str_node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak or deprecated TLS/SSL protocol version configured. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    name_has_field(v.name, tls_proto_fields)
    walk(v.value, [_, str_node])
    str_node.ir_type == "String"
    regex.match(weak_tls_pattern, str_node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak or deprecated TLS/SSL protocol version configured. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    name_has_field(attr.name, key_size_fields)
    attr.value.ir_type == "Integer"
    attr.value.value > 0
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Insufficient cryptographic key length. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    name_has_field(attr.name, dh_group_fields)
    attr.value.ir_type == "Integer"
    attr.value.value >= 1
    attr.value.value <= 2
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak Diffie-Hellman group detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    regex.match("(?i).*(hash|digest|encrypt|sign).*", node.name)
    arg := node.args[_]
    arg.ir_type == "String"
    regex.match(weak_algo_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic function call detected. (CWE-326)"
    }
}