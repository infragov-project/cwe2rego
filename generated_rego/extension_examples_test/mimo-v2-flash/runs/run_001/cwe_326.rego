package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)(algorithm|cipher|encryption_algorithm|key_algorithm|protocol|ssl_policy|tls_version|ssl_version|min_tls_version|cipher_suites|ciphers|allowed_ciphers|key_length|key_size|bits|encryption_key_size)", attr.name)
    glitch_lib.traverse(attr.value, "(?i)(des|3des|rc4|aes-128|sha-1|des-cbc3-sha|rc4-md5|sslv2|sslv3|tls1\\.0|tls1\\.1|cbc|export|null)")
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption configuration detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)(key_length|key_size|bits|encryption_key_size)", attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length. (CWE-326)"
    }
}