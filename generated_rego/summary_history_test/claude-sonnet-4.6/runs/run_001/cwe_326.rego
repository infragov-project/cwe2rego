package glitch

import data.glitch_lib

crypto_name_pattern := "(?i).*(algorithm|cipher|encrypt|hash|digest|sign|tls_version|ssl_version|protocol_version|tls_policy|ssl_policy|security_policy|dh_group|ecdh_curve|key_exchange|ipsec_policy|tunnel_enc|phase[12]_enc|key_type|key_spec|auth_method|auth_type).*"

key_size_name_pattern := "(?i)^(key_size|key_length|rsa_bits|key_bits|modulus_length|bit_length)$"

weak_func_name_pattern := "(?i)^(md[2-5]|sha-?1|des|3des|tripledes|rc[2-5]|blowfish)$"

is_weak_value(value) {
    regex.match("(?i)^(des|3des|tripledes|rc[245]|blowfish|idea|md5|sha-?1|sslv[23]|tlsv1[.][01]|tls_1_[01]|group[125]|rsa_1024|ec_prime192v1|md5_crypt|sha1_crypt|des_crypt)$", value)
}

is_weak_value(value) {
    regex.match("(?i).*(md5|sha1|sha-1|3des|tripledes|rc4|rc2|des_crypt|md5_crypt|sha1_crypt|sslv[23]|tlsv1[.][01]|tls_1_[01]).*", value)
}

is_weak_value(value) {
    regex.match("(?i).*_sha[^0-9].*", value)
}

is_weak_value(value) {
    regex.match("(?i).*_sha$", value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(crypto_name_pattern, attr.name)
    attr.value.ir_type == "String"
    is_weak_value(attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or deprecated cryptographic algorithm detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(crypto_name_pattern, v.name)
    v.value.ir_type == "String"
    is_weak_value(v.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or deprecated cryptographic algorithm in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(crypto_name_pattern, attr.name)
    attr.value.ir_type == "Array"
    item := attr.value.value[_]
    item.ir_type == "String"
    is_weak_value(item.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak algorithm in cipher list. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "FunctionCall"
    regex.match(weak_func_name_pattern, attr.value.name)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic function used. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    v.value.ir_type == "FunctionCall"
    regex.match(weak_func_name_pattern, v.value.name)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic function used in variable assignment. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "FunctionCall"
    regex.match("(?i).*(hash|crypt|encrypt|sign|digest|hmac).*", attr.value.name)
    arg := attr.value.args[_]
    arg.ir_type == "String"
    is_weak_value(arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak algorithm in cryptographic function call. (CWE-326)"
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
    regex.match(crypto_name_pattern, entry.key.value)
    entry.value.ir_type == "String"
    is_weak_value(entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.key,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm in nested structure. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(key_size_name_pattern, attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value <= 1024
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Key size too small. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(key_size_name_pattern, v.name)
    v.value.ir_type == "Integer"
    v.value.value <= 1024
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Inadequate encryption strength - Key size too small. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr, [_, access_node])
    access_node.ir_type == "Access"
    access_node.right.ir_type == "String"
    is_weak_value(access_node.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm reference in variable access. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    walk(v, [_, access_node])
    access_node.ir_type == "Access"
    access_node.right.ir_type == "String"
    is_weak_value(access_node.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm reference in variable access. (CWE-326)"
    }
}