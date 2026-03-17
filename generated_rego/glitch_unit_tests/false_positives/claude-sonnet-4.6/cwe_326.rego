package glitch

import data.glitch_lib

weak_algo_exact := {"des", "3des", "triple_des", "rc2", "rc4", "rc5", "arc4", "arcfour", "blowfish", "idea", "md5", "sha1", "sha-1", "md4", "md2"}

weak_tls_values := {"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tls_1_0", "tlsv1.1", "tls_1_1"}

tls_attr_names := {"ssl_policy", "security_policy", "minimum_protocol_version", "tls_version", "tls_policy", "protocol_version", "min_tls_version"}

key_size_attrs := {"key_size", "key_length", "rsa_bits", "key_bits", "bit_length", "modulus_length"}

weak_crypto_pattern := "(?i).*(md5|sha-?1|md[24]|3des|triple.?des|rc[245]|arc4|arcfour|blowfish)"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == weak_algo_exact[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or broken cryptographic algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    walk(v.value, [_, n])
    n.ir_type == "MethodCall"
    n.receiver.ir_type == "VariableReference"
    regex.match(weak_crypto_pattern, n.receiver.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm used in method call. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, n])
    n.ir_type == "FunctionCall"
    arg := n.args[_]
    arg.ir_type == "String"
    lower(arg.value) == weak_algo_exact[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak algorithm passed to cryptographic function. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, n])
    n.ir_type == "VariableReference"
    regex.match(weak_crypto_pattern, n.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Reference to weak cryptographic algorithm in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == key_size_attrs[_]
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Key size below minimum threshold. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == tls_attr_names[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == weak_tls_values[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or deprecated TLS/SSL protocol version. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"encryption_mode", "cipher_mode", "block_mode"}[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == "ecb"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - ECB cipher mode is cryptographically weak. (CWE-326)"
    }
}