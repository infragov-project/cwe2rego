package glitch

import data.glitch_lib

weak_algorithm_names := {"algorithm", "cipher", "encryption_type", "crypto_method"}
weak_key_names := {"key_length", "key_size", "key_bits", "key_rotation"}
weak_protocol_names := {"ssl_version", "tls_version", "protocol_version", "cipher_suites"}
weak_data_names := {"encryption_enabled", "storage_encryption", "transit_encryption", "data_protection"}
weak_storage_names := {"server_side_encryption", "storage_encryption", "database_encryption", "encryption_key_id", "kms_key_id"}
weak_network_names := {"ssl_policy", "tls_version", "security_policy", "encryption_protocol"}

weak_algorithm_pattern := "DES|3DES|RC4|MD5|SHA1|AES-128|RSA-1024|SSLv2|SSLv3|TLS 1\\.0|TLS 1\\.1"
weak_key_pattern := "^(1024|128)$"
weak_protocol_pattern := "SSLv2|SSLv3|TLS 1\\.0|TLS 1\\.1"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    weak_algorithm_names[attr.name]
    glitch_lib.traverse(attr, weak_algorithm_pattern)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected - Use of deprecated or weak encryption algorithms. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    weak_key_names[attr.name]
    (attr.value.ir_type == "String" and regex.match(weak_key_pattern, attr.value.value)) or
    (attr.value.ir_type == "Integer" and attr.value.value < 2048)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak key management - Key sizes below current standards or missing key rotation. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    weak_protocol_names[attr.name]
    glitch_lib.traverse(attr, weak_protocol_pattern)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak protocol configuration - Outdated TLS/SSL versions or weak cipher suites. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    (weak_data_names[attr.name] or weak_storage_names[attr.name] or weak_network_names[attr.name])
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate data protection - Encryption disabled for sensitive data stores. (CWE-326)"
    }
}