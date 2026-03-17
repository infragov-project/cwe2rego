package glitch

import data.glitch_lib

weak_encryption_algorithms := {"DES", "3DES", "RC4", "MD5", "SHA1", "MD4", "PBKDF1", "XOR", "SHA-1"}

weak_key_lengths := {64, 128}

weak_modes := {"ECB"}

weak_tls_versions := {"TLSv1", "SSLv3"}

weak_cipher_suites := {"TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_RC4_128_SHA"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    (attr.name == "cipher" or attr.name == "algorithm" or attr.name == "encryption" or attr.name == "encryption_type")
    attr.value.ir_type == "String"
    glitch_lib.check_string(attr.value, weak_encryption_algorithms)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak encryption algorithm or cipher. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    (attr.name == "key_length" or attr.name == "keySize")
    attr.value.ir_type == "Integer"
    key_length := attr.value.value
    key_length < 128

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of insufficient key length for encryption. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    (attr.name == "mode")
    attr.value.ir_type == "String"
    glitch_lib.check_string(attr.value, weak_modes)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of insecure cipher mode (e.g. ECB). (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    (attr.name == "iterations" or attr.name == "count")
    attr.value.ir_type == "Integer"
    iterations := attr.value.value
    iterations < 1000

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of low iteration count in key derivation. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    (attr.name == "salt" or attr.name == "salt_value")
    attr.value.ir_type == "String"
    salt_value := attr.value.value
    regex.match("(?i)^(admin|default|test|password|secret|sample|123456|$)", salt_value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of hardcoded or predictable salt in encryption. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    (attr.name == "key" or attr.name == "secret")
    attr.value.ir_type == "String"
    key_value := attr.value.value
    regex.match("(?i)^(password|key|secret|pass|123|abc|default|test|admin|root|$)", key_value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of hardcoded or weak encryption key. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    (attr.name == "enforce_encryption" or attr.name == "encryption")
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption explicitly disabled. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    (attr.name == "tls_version" or attr.name == "cipher_suites")
    attr.value.ir_type == "String"
    glitch_lib.check_string(attr.value, weak_tls_versions + weak_cipher_suites)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak TLS version or cipher suite. (CWE-326)"
    }
}