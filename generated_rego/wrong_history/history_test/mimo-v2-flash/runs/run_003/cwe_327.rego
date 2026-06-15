package glitch

import data.glitch_lib

weak_crypto_indicators := {"DES", "3DES", "RC4", "Blowfish", "CAST", "IDEA", "MD2", "MD4", "MD5", "SHA1", "ECB", "XOR", "ROT13", "Base64", "SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1", "DH", "RSA"}

check_algorithm(value) {
    value.ir_type == "String"
    some indicator in weak_crypto_indicators
    regex.match(sprintf("(?i).*%s.*", [indicator]), value.value)
}

check_key_length(value) {
    value.ir_type == "Integer"
    value.value < 2048
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    check_algorithm(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "key_size"
    check_key_length(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a weak cryptographic key length (CWE-327)"
    }
}