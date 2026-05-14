package glitch

import data.glitch_lib

# Define weak crypto patterns (case-insensitive)
weak_crypto_patterns := {
    "des", "3des", "rc4", "aes-128", "blowfish", "idea", "rsa-1024",
    "ssl", "sslv2", "sslv3", "tls_1_0", "tls_1_1", "tls-1-0", "tls-1-1",
    "md5", "sha1", "sha-1", "md5_crypt", "cbc", "export", "null", "anon"
}

# Helper rule to check if a string contains weak crypto patterns
contains_weak_crypto(str) {
    regex.match("(?i)(des|3des|rc4|aes[-_]?128|blowfish|idea|rsa[-_]?1024|sslv?2|sslv?3|tls[ _-]?1[._-]0|tls[ _-]?1[._-]1|md5|sha[-_]?1|md5_crypt|cbc|export|null|anon)", str)
}

# Helper rule to check if a value contains weak crypto patterns
check_weak_crypto(value) {
    value.ir_type == "String"
    contains_weak_crypto(value.value)
} else {
    value.ir_type == "FunctionCall"
    contains_weak_crypto(value.name)
} else {
    value.ir_type == "Access"
    contains_weak_crypto(value.right.value)
} else {
    value.ir_type == "Hash"
    pair := value.value[_]
    pair.key.ir_type == "String"
    contains_weak_crypto(pair.key.value)
} else {
    value.ir_type == "Array"
    walk(value, [path, element])
    element.ir_type == "String"
    contains_weak_crypto(element.value)
}

# Main detection rule for weak crypto in Attributes (e.g., Ansible attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]

    # Check attribute name context to avoid false positives
    attr.name != ""
    regex.match("(?i)(cipher|ssl|tls|encrypt|hash|password|auth|algorithm)", attr.name)

    # Check value for weak patterns
    check_weak_crypto(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm or protocol detected (CWE-326)"
    }
}

# Main detection rule for weak crypto in Variables (e.g., Puppet variables)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_vars := glitch_lib.all_variables(parent)
    var := all_vars[_]

    # Check variable name context
    regex.match("(?i)(password|auth|hash|ssl|tls|signature|cipher|algorithm)", var.name)

    # Check value for weak patterns
    check_weak_crypto(var.value)

    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic hashing detected in variable (CWE-326)"
    }
}