package glitch

import data.glitch_lib

weak_crypto_patterns := {
    "(?i)\\bdes\\b",
    "(?i)\\b3des\\b",
    "(?i)\\brc4\\b",
    "(?i)\\btea\\b",
    "(?i)\\bxor\\b",
    "(?i)\\brot[- ]?13\\b",
    "(?i)\\bmd5\\b",
    "(?i)\\bsha[- ]?1\\b",
    "(?i)\\bsha1\\b",
    "(?i)\\blanman\\b",
    "(?i)\\bntlm\\b",
    "(?i)\\brsa[- ]?1024\\b",
    "(?i)\\bdsa[- ]?1024\\b",
    "(?i)\\becdsa[- ]?secp192r1\\b",
    "(?i)\\bsslv2\\b",
    "(?i)\\bsslv3\\b",
    "(?i)\\btls[\\s]?1\\.0\\b",
    "(?i)\\btls[\\s]?1\\.1\\b",
    "(?i)\\bsshv1\\b",
    "(?i)\\bexport\\b",
    "(?i)\\bnull\\b",
    "(?i)\\banon\\b",
    "(?i)\\bcustom\\b",
    "(?i)\\binsecure\\b",
    "(?i)\\blegacy\\b",
    "(?i)\\bmd5_crypt\\b",
    "(?i)\\baes[- ]?128\\b"
}

contains_weak_crypto(value) {
    pattern := weak_crypto_patterns[_]
    glitch_lib.traverse(value, pattern)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    contains_weak_crypto(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using broken or risky cryptographic algorithms (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    contains_weak_crypto(var.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using broken or risky cryptographic algorithms (CWE-327)"
    }
}