package glitch

import data.glitch_lib

algorithm_attributes := {"algorithm", "encryption_algorithm", "cipher", "block_cipher_mode", "kms_key_spec", "customer_master_key_spec"}
key_length_attributes := {"key_length", "key_size", "bit_length", "rsakey_bits"}
salt_iv_attributes := {"salt", "initialization_vector", "iv", "nonce"}
protocol_attributes := {"protocol", "ssl_protocol", "tls_version", "disabled_algorithms"}

weak_algorithm_strings := {"DES", "Single DES", "DESede", "AES-128", "RC2", "RC4", "Blowfish", "Twofish", "ARC4", "MD5", "SHA-1"}
weak_key_lengths := {56, 64, 128, 512, 1024}
weak_static_values := {"12345", "0000", "static", "password", "admin", "123456"}
deprecated_protocols := {"TLSv1.0", "TLSv1.1", "SSLv3", "TLS_1_0", "TLS_1_1", "SSLv3"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    algorithm_attributes[attr.name]
    attr.value.ir_type == "String"
    weak_algorithm_strings[attr.value.value]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm - Use of inadequate encryption strength (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    key_length_attributes[attr.name]
    attr.value.ir_type == "Integer"
    weak_key_lengths[attr.value.value]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak key length - Use of inadequate encryption strength (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    salt_iv_attributes[attr.name]
    attr.value.ir_type == "String"
    weak_static_values[attr.value.value]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Static salt or IV - Use of inadequate encryption strength (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "iterations"
    attr.value.ir_type == "Integer"
    attr.value.value < 10000
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Low KDF iterations - Use of inadequate encryption strength (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    protocol_attributes[attr.name]
    attr.value.ir_type == "String"
    deprecated_protocols[attr.value.value]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Deprecated protocol - Use of inadequate encryption strength (CWE-326)"
    }
}