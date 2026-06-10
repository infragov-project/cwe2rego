package glitch

import data.glitch_lib

weak_algorithm_attributes := {"algorithm", "cipher", "encryption_type", "encryption_method", "hashing_algorithm", "signature_algorithm", "digest"}
weak_algorithm_pattern := "DES|3DES|RC4|AES-128|SHA-1|MD5|HMAC-SHA1|SSLv2|SSLv3|TLS 1.0|TLS 1.1|SSL"

insufficient_key_attributes := {"key_size", "key_length", "bit_length", "encryption_bits"}

outdated_protocol_attributes := {"protocol", "tls_version", "ssl_policy", "min_tls_version"}
outdated_protocol_pattern := "TLS 1.0|TLS 1.1|SSL|legacy_mode"

encryption_disabled_attributes := {"enable_encryption", "server_side_encryption", "encryption_enabled"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == weak_algorithm_attributes[_]
    attr.value.ir_type == "String"
    regex.match(sprintf("(?i).*%s.*", [weak_algorithm_pattern]), attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected - Avoid using weak encryption algorithms such as DES, 3DES, RC4, AES-128, SHA-1, MD5, HMAC-SHA1, SSLv2, SSLv3, TLS 1.0, TLS 1.1, or SSL. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == insufficient_key_attributes[_]
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length detected - Key sizes should be at least 2048 bits for RSA and 256 bits for AES. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == outdated_protocol_attributes[_]
    attr.value.ir_type == "String"
    regex.match(sprintf("(?i).*%s.*", [outdated_protocol_pattern]), attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Outdated protocol detected - Avoid using outdated protocols such as TLS 1.0, TLS 1.1, SSL, or legacy_mode. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == encryption_disabled_attributes[_]
    (attr.value.ir_type == "Boolean" and attr.value.value == false) or
    (attr.value.ir_type == "String" and attr.value.value == "false")
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled - Encryption should be enabled for sensitive data. (CWE-326)"
    }
}