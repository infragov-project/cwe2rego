package glitch

import data.glitch_lib

weak_algo_exact(v) {
    v.ir_type == "String"
    regex.match("(?i)^(md5|sha-?1|sha1|md4|md2|md5_crypt|sha1_crypt|des|3des|tdea|rc4|rc2|blowfish)$", v.value)
}

weak_algo_substring(v) {
    v.ir_type == "String"
    regex.match("(?i).*(\\bDES\\b|3DES|TDEA|\\bRC4\\b|\\bRC2\\b|BLOWFISH|CBC_SHA|EXPORT|md5_crypt|sha1_crypt).*", v.value)
}

weak_tls(v) {
    v.ir_type == "String"
    regex.match("(?i).*(SSLv2|SSLv3|TLSv?1\\.0|TLSv?1\\.1|TLS_1_0|TLS_1_1|ELBSecurityPolicy-2016-08).*", v.value)
}

weak_curve(v) {
    v.ir_type == "String"
    regex.match("(?i).*(P-192|P-224|secp192r1|secp224r1|sect163k1).*", v.value)
}

weak_key_size(v) {
    v.ir_type == "Integer"
    v.value < 2048
}

weak_func_name(name) { regex.match("(?i)^(md5|sha-?1|sha1|md4|md2|des|3des|rc4|rc2|blowfish)$", name) }

is_tls_key(name) { regex.match("(?i).*(ssl_policy|security_policy|minimum_protocol_version|min_tls_version|tls_version|ssl_version|protocol).*", name) }

is_curve_key(name) { regex.match("(?i).*(ecdsa_curve|elliptic_curve|curve_name).*", name) }

is_key_size_key(name) { regex.match("(?i).*(key_size|key_length|key_bits|rsa_bits|modulus_length|key_spec).*", name) }

is_crypto_key(name) { regex.match("(?i).*(algorithm|cipher|encrypt|hash|digest|signing|auth_method|auth_type|authentication).*", name) }

weak_algo_in_access_key(v) {
    v.ir_type == "Access"
    v.right.ir_type == "String"
    regex.match("(?i).*(md5|sha-?1|sha1|md4|md2|des|3des|rc4|rc2|blowfish).*", v.right.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    weak_algo_exact(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_crypto_key(attr.name)
    weak_algo_substring(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm in configuration (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_tls_key(attr.name)
    weak_tls(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak TLS/SSL protocol version (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_curve_key(attr.name)
    weak_curve(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak elliptic curve selected (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_key_size_key(attr.name)
    weak_key_size(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Insufficient key size (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    weak_algo_in_access_key(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm reference in access key (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    weak_algo_exact(v.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm in variable (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_crypto_key(v.name)
    weak_algo_substring(v.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm in variable (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    weak_func_name(node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic function call (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    arg := node.args[_]
    arg.ir_type == "String"
    regex.match("(?i)^(md5|sha-?1|sha1|md4|md2|des|3des|rc4|rc2|blowfish)$", arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm passed to function (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    is_crypto_key(entry.key.value)
    entry.value.ir_type == "String"
    weak_algo_exact(entry.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm in nested configuration (CWE-326)"
    }
}