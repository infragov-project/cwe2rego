package glitch

import data.glitch_lib

key_size_attrs := {"key_size", "rsa_bits", "key_length", "bit_length", "modulus_bits", "key_bits"}

weak_algo_attrs := {"algorithm", "encryption_algorithm", "cipher", "cipher_suite", "sse_algorithm", "cipher_list", "cipher_suites", "ssl_ciphers", "security_protocol"}

weak_tls_attrs := {"ssl_policy", "minimum_tls_version", "min_tls_version", "tls_min_version", "security_policy", "protocol_version", "tls_policy", "ssl_protocol", "ssl_protocols", "enabled_ssl_protocols"}

weak_hash_attrs := {"hash_algorithm", "signing_algorithm", "digest_algorithm", "certificate_signing_algorithm", "signature_algorithm", "integrity_algorithm", "digest_algo", "content_md5"}

weak_key_type_attrs := {"key_spec", "key_algorithm", "key_type", "certificate_type", "public_key_type", "type"}

weak_vpn_attrs := {"phase1_encryption_algorithm", "phase2_encryption_algorithm", "dh_group", "pfs_group"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.name == key_size_attrs[_]
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Key size below recommended minimum. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    regex.match("(?i)(openssl|dhparam|privatekey|certificate|crypto|rsa|ecdsa|dsa|key_pair|keypair)", node.type)
    size_a := node.attributes[_]
    size_a.name == "size"
    size_a.value.ir_type == "Integer"
    size_a.value.value < 2048
    report_a := node.attributes[_]
    report_a.name != "size"
    count({other | other := node.attributes[_]; other.name != "size"; other.line < report_a.line}) == 0
    result := {
        "type": "sec_weak_crypt",
        "element": report_a,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Key/DH parameter size below recommended minimum. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.name == weak_algo_attrs[_]
    glitch_lib.traverse(attr.value, "(?i)\\b(DES|3DES|RC2|RC4|RC5|Blowfish|ECB|AES56|AES64|EXPORT|NULL|ANON)\\b")
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak or deprecated encryption algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.name == weak_tls_attrs[_]
    glitch_lib.traverse(attr.value, "(?i)(SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1|TLS_1_0|TLS_1_1|ELBSecurityPolicy-2015|TLSv1([^.0-9]|$))")
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak or deprecated TLS/SSL protocol version. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.name == weak_hash_attrs[_]
    glitch_lib.traverse(attr.value, "(?i)\\b(MD5|SHA-?1)\\b")
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak or deprecated hash/signing algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.name == weak_key_type_attrs[_]
    glitch_lib.traverse(attr.value, "(?i)(RSA_1024|DSA_1024|EC_prime192v1|ssh-dss)")
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak key type or key specification. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.name == weak_vpn_attrs[_]
    glitch_lib.traverse(attr.value, "(?i)(group1|group2|group5|modp1024|modp768)")
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak VPN/IPSec DH group or encryption parameters. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.value.ir_type == "Hash"
    entry := attr.value.value[_]
    entry.key.ir_type == "String"
    glitch_lib.contains(entry.key.value, weak_algo_attrs[_])
    glitch_lib.traverse(entry.value, "(?i)\\b(DES|3DES|RC2|RC4|RC5|Blowfish|ECB|AES56|AES64|EXPORT|NULL|ANON)\\b")
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak or deprecated encryption algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.value.ir_type == "Hash"
    entry := attr.value.value[_]
    entry.key.ir_type == "String"
    glitch_lib.contains(entry.key.value, weak_tls_attrs[_])
    glitch_lib.traverse(entry.value, "(?i)(SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1|TLS_1_0|TLS_1_1|ELBSecurityPolicy-2015|TLSv1([^.0-9]|$))")
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak or deprecated TLS/SSL protocol version. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attr := node.attributes[_]
    attr.value.ir_type == "Hash"
    entry := attr.value.value[_]
    entry.key.ir_type == "String"
    glitch_lib.contains(entry.key.value, weak_hash_attrs[_])
    glitch_lib.traverse(entry.value, "(?i)\\b(MD5|SHA-?1)\\b")
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak or deprecated hash/signing algorithm. (CWE-326)"
    }
}