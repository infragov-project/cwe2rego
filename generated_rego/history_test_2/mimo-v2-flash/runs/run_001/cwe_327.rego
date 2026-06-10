package glitch

import data.glitch_lib

weak_crypto_patterns := {
    "DES", "3DES", "RC4", "MD5", "SHA1", "SHA-1", "SSLv2", "SSLv3", "TLS1.0", "TLS1.1", "ECB", "ROT-25", "XOR"
}

check_weak_crypto(value) {
    value.ir_type == "String"
    pattern := weak_crypto_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    check_weak_crypto(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm (CWE-327)"
    }
}