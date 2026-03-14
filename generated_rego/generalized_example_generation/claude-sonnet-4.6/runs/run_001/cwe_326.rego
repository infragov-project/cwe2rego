package glitch

import data.glitch_lib

alg_names := {"algorithm", "encryption_algorithm", "key_algorithm", "cipher", "key_spec", "key_type"}
key_size_names := {"key_size", "key_length", "key_bits", "rsa_bits", "modulus_length", "dh_param_size", "dh_key_size"}
tls_names := {"ssl_policy", "tls_policy", "minimum_tls_version", "min_tls_version", "ssl_protocol", "protocol_version", "security_policy", "tls_version", "enabled_protocols"}
cipher_names := {"cipher_suite", "ssl_ciphers", "cipher_policy", "cipher_list", "enabled_ssl_protocols"}
digest_names := {"signature_algorithm", "hash_algorithm", "digest_algorithm", "signing_algorithm", "certificate_algorithm"}
curve_names := {"elliptic_curve", "named_curve", "curve_name"}
disable_enc_names := {"encrypted", "storage_encrypted", "encryption_enabled", "at_rest_encryption_enabled", "transit_encryption_enabled", "ssl_enforce", "require_ssl", "enforce_https"}
allow_insec_names := {"allow_insecure", "insecure_ssl", "allow_unencrypted_connections"}

weak_alg_set := {"des", "3des", "triple_des", "rc4", "rc2", "rc5", "blowfish", "cast5", "idea", "rsa_1024", "rsa_512", "dsa_1024", "md5", "sha1", "sha-1"}
weak_digest_set := {"md5", "sha1", "sha-1", "md5withrsaencryption", "sha1withrsaencryption"}
weak_cipher_words := {"NULL", "EXPORT", "anon", "ADH", "AECDH", "RC4", "DES", "3DES", "MD5", "LOW", "WEAK"}
weak_curve_values := {"secp112r1", "secp128r1", "secp160r1", "prime192v1", "P-192"}
weak_tls_pattern := "(?i)^(SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1|TLSv1|TLS1\\.0|TLS1\\.1|TLSv1_1|TLS_1_0|TLS_1_1|TLS1_0|TLS1_1)$"

kv_name(n) = name {
    n.ir_type == "Attribute"
    name := lower(n.name)
}

kv_name(n) = name {
    not n.ir_type
    n.key.ir_type == "String"
    name := lower(trim_suffix(n.key.value, ":"))
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    kv_name(n) == alg_names[_]
    n.value.ir_type == "String"
    lower(n.value.value) == weak_alg_set[_]
    result := {
        "type": "sec_weak_crypt",
        "element": n.value,
        "path": parent.path,
        "description": "Weak or deprecated encryption algorithm detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    kv_name(n) == key_size_names[_]
    n.value.ir_type == "Integer"
    n.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": n.value,
        "path": parent.path,
        "description": "Insufficient cryptographic key size. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    kv_name(n) == tls_names[_]
    n.value.ir_type == "String"
    regex.match(weak_tls_pattern, n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n.value,
        "path": parent.path,
        "description": "Weak or deprecated TLS/SSL version detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    kv_name(n) == tls_names[_]
    n.value.ir_type == "Array"
    item := n.value.value[_]
    item.ir_type == "String"
    regex.match(weak_tls_pattern, item.value)
    result := {
        "type": "sec_weak_crypt",
        "element": item,
        "path": parent.path,
        "description": "Weak TLS/SSL version in array configuration. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    kv_name(n) == cipher_names[_]
    n.value.ir_type == "String"
    glitch_lib.contains(n.value.value, weak_cipher_words[_])
    result := {
        "type": "sec_weak_crypt",
        "element": n.value,
        "path": parent.path,
        "description": "Weak cipher suite detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "String"
    regex.match("(?i).*(ssl_ciphers|cipher_suite|cipher_list).*", node.value)
    glitch_lib.contains(node.value, weak_cipher_words[_])
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak cipher suite in configuration content. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    kv_name(n) == digest_names[_]
    n.value.ir_type == "String"
    lower(n.value.value) == weak_digest_set[_]
    result := {
        "type": "sec_weak_crypt",
        "element": n.value,
        "path": parent.path,
        "description": "Weak digest or signature algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    kv_name(n) == curve_names[_]
    n.value.ir_type == "String"
    glitch_lib.contains(n.value.value, weak_curve_values[_])
    result := {
        "type": "sec_weak_crypt",
        "element": n.value,
        "path": parent.path,
        "description": "Weak elliptic curve detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Attribute"
    lower(n.name) == disable_enc_names[_]
    n.value.ir_type == "Boolean"
    n.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Encryption or SSL/TLS enforcement is disabled. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Attribute"
    lower(n.name) == allow_insec_names[_]
    n.value.ir_type == "Boolean"
    n.value.value == true
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Insecure connections explicitly permitted. (CWE-326)"
    }
}