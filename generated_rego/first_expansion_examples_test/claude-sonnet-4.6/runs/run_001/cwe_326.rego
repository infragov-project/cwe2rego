package glitch

import data.glitch_lib

weak_algo_segment := "(?i)(^|.*[-_])(md5|sha[-_]?1|des|3des|rc4|rc2|blowfish)([-_].*|$)"

weak_algo_exact := "(?i)^(md5|sha[-_]?1|des|3des|rc4|rc2|blowfish)$"

is_weak_algo_str(val) {
    regex.match(weak_algo_segment, val)
}

is_weak_algo_exact(val) {
    regex.match(weak_algo_exact, val)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "FunctionCall"
    regex.match("(?i).*(hash|digest|crypt|hmac).*", attr.value.name)
    arg := attr.value.args[_]
    arg.ir_type == "String"
    is_weak_algo_exact(arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak algorithm used in hash/crypt function. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i).*(algorithm|cipher|auth_method|auth_type|hash_type|digest|key_spec|key_alg).*", attr.name)
    attr.value.ir_type == "String"
    is_weak_algo_exact(attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak algorithm specified in attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Access"
    attr.value.right.ir_type == "String"
    is_weak_algo_str(attr.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Access to key referencing a weak algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i).*(rsa_bits|key_size|key_length|key_bits|key_strength|bit_length).*", attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value > 0
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Key size is too small for adequate security. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i).*(ssl_policy|tls_policy|min_tls|minimum_tls|ssl_protocol|tls_version|security_policy).*", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i).*(sslv[23]|tlsv?1\\.0|tlsv?1\\.1|tls[_-]1[_-][01]).*", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak TLS/SSL protocol version configured. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i).*(encryption_enabled|in_transit_encryption|at_rest_encryption|require_ssl|enforce_https).*", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Encryption is explicitly disabled. (CWE-326)"
    }
}