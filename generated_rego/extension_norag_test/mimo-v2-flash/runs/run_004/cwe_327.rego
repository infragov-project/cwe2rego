package glitch

import data.glitch_lib

weak_crypto_strings := {"md5", "sha1", "des", "3des", "rc4", "ecb", "sslv2", "sslv3", "tls_1.0", "tls_1.1", "md5_crypt"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    glitch_lib.traverse(node, weak_crypto_strings)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken cryptographic algorithm or protocol - Avoid using broken or risky cryptographic algorithms. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    glitch_lib.traverse(var.value, weak_crypto_strings)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of broken cryptographic algorithm or protocol in variable - Avoid using broken or risky cryptographic algorithms. (CWE-327)"
    }
}