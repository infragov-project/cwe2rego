package glitch

import data.glitch_lib

weak_algorithms = {"DES", "3DES", "RC4", "Blowfish", "AES-128", "SHA-1", "MD5"}
protocol_attributes = {"protocol_version", "tls_version", "ssl_version", "min_tls_version"}
deprecated_protocols = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
mode_attributes = {"encryption_mode", "block_cipher_mode"}
insecure_modes = {"ECB"}
key_size_attributes = {"key_size", "key_length", "bits", "encryption_key_size"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "algorithm"
    attr.value.ir_type == "String"
    some weak_alg
    weak_alg = weak_algorithms[_]
    regex.match(sprintf("(?i).*%s.*", [weak_alg]), attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm - Use of weak encryption algorithm (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == protocol_attributes[_]
    attr.value.ir_type == "String"
    some protocol
    protocol = deprecated_protocols[_]
    regex.match(sprintf("(?i).*%s.*", [protocol]), attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Deprecated protocol - Use of deprecated protocol (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == mode_attributes[_]
    attr.value.ir_type == "String"
    some mode
    mode = insecure_modes[_]
    regex.match(sprintf("(?i).*%s.*", [mode]), attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure encryption mode - Use of insecure encryption mode (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == key_size_attributes[_]
    attr.value.ir_type == "Integer"
    attr.value.value < 128
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Low key size - Use of weak encryption key size (CWE-326)"
    }
}