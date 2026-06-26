package glitch

import data.glitch_lib

weak_tls_names := {"ssl_policy", "tls_policy", "security_policy", "min_tls_version", "minimum_tls_version", "min_protocol_version", "tls_version", "protocol_version"}

weak_key_names := {"key_size", "key_length", "rsa_bits", "bit_length", "key_bits", "modulus_length"}

weak_algo_names := {"algorithm", "encryption_algorithm", "cipher", "cipher_type", "cipher_suite", "cipher_suites", "enabled_ssl_protocols", "allowed_ciphers", "ssl_cipher", "encrypt"}

weak_hash_names := {"signing_algorithm", "certificate_algorithm", "hash_algorithm", "digest_algorithm", "signature_algorithm", "auth_method"}

weak_curve_names := {"curve_name", "elliptic_curve", "curve_type", "named_curve"}

weak_key_spec_names := {"key_spec", "customer_master_key_spec", "kms_key_spec"}

weak_tls_regex := "(?i).*(SSLv2|SSLv3|TLSv?1\\.0|TLSv?1\\.1|TLS_1_0|TLS_1_1|SSL_3_0).*"
weak_algo_regex := "(?i).*(3DES|TRIPLE.DES|RC2|RC4|ARC4|ARCFOUR|Blowfish|IDEA|MD5|MD4|SHA1|SHA-1).*"
weak_hash_regex := "(?i).*(MD4|MD5|SHA1|SHA-1|SHA1WithRSA|MD5WithRSA|ecdsa.with.SHA1).*"
weak_curve_regex := "(?i).*(secp192r1|prime192v1|secp160r1|sect163k1).*"
weak_key_spec_regex := "(?i).*(RSA_512|RSA_768|RSA_1024).*"
weak_standalone_regex := "(?i)^(MD5|MD4|SHA1|SHA-1|SHA1WithRSA|MD5WithRSA|DES|3DES|RC2|RC4|ARC4|ARCFOUR|Blowfish|IDEA|SSLv2|SSLv3|TLSv1|TLSv1\\.0|TLSv1\\.1|TLS_1_0|TLS_1_1|SSL_3_0|secp192r1|prime192v1|secp160r1|sect163k1)$"
weak_identifier_regex := "(?i).*(md5|md4|sha1|sha[-_]1|3des|triple[-_]des|rc[24]|arc4|blowfish|sslv[23]|tls1[_\\.]0|tls1[_\\.]1).*"

name_matches_any(name, names) {
    n := names[_]
    regex.match(sprintf("(?i).*%s.*", [n]), name)
}

is_weak_by_name_value(name, value) {
    name_matches_any(name, weak_tls_names)
    regex.match(weak_tls_regex, value)
}

is_weak_by_name_value(name, value) {
    name_matches_any(name, weak_algo_names)
    regex.match(weak_algo_regex, value)
}

is_weak_by_name_value(name, value) {
    name_matches_any(name, weak_hash_names)
    regex.match(weak_hash_regex, value)
}

is_weak_by_name_value(name, value) {
    name_matches_any(name, weak_curve_names)
    regex.match(weak_curve_regex, value)
}

is_weak_by_name_value(name, value) {
    name_matches_any(name, weak_key_spec_names)
    regex.match(weak_key_spec_regex, value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "String"
    is_weak_by_name_value(node.name, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cryptographic algorithm or protocol version configured. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "String"
    is_weak_by_name_value(node.name, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cryptographic algorithm or protocol version configured. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "String"
    regex.match(weak_standalone_regex, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cryptographic algorithm value detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "String"
    regex.match(weak_standalone_regex, node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cryptographic algorithm value detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "Access"
    node.value.right.ir_type == "String"
    regex.match(weak_identifier_regex, node.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cryptographic algorithm referenced via attribute access. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    name_matches_any(node.name, weak_key_names)
    node.value.ir_type == "Integer"
    node.value.value > 0
    node.value.value <= 1024
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Insufficient asymmetric key length - Use at least 2048 bits. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    name_matches_any(node.name, weak_key_names)
    node.value.ir_type == "Integer"
    node.value.value > 0
    node.value.value <= 1024
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Insufficient asymmetric key length - Use at least 2048 bits. (CWE-326)"
    }
}