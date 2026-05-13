package glitch

import data.glitch_lib

weak_crypto_values := {
    "DES", "3DES", "RC4", "MD5", "SHA1", "RSA-1024", "RSA_1024",
    "ECDSA-160", "ECDSA_160", "XOR", "Blowfish", "TEA", "XTEA",
    "ROT13", "ROT25", "custom", "SSLv2", "SSLv3", "TLS 1.0",
    "TLS_1_0", "TLS 1.1", "TLS_1_1", "PBKDF1", "DSA_1024",
    "proprietary", "obfuscation", "md5_crypt", "md5", "sha1"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    glitch_lib.traverse(attr.value, weak_crypto_values)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    glitch_lib.traverse(var.value, weak_crypto_values)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm (CWE-327)"
    }
}