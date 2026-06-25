package glitch

import data.glitch_lib

weak_key_size_threshold := 2048

key_size_names := {"key_size", "key_bits", "rsa_bits", "dsa_bits", "key_length", "bits"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    lower(attr.name) == key_size_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value < weak_key_size_threshold

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Key size is too small and susceptible to brute force attacks. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.value.ir_type == "String"
    regex.match("(?i)^(des|3des|triple.?des|rc4|rc2|blowfish|idea|seed|rc5)$", attr.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Use of weak encryption algorithm susceptible to brute force attacks. (CWE-326)"
    }
}