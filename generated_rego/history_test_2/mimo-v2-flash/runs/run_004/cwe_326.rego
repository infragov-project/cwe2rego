package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    weak_algorithms := {"DES", "3DES", "RC4", "AES-128", "MD5", "SHA-1", "SSLv2", "SSLv3", "TLS_1_0", "TLS_1_1", "RSA-1024"}
    attr.value.ir_type == "String"
    attr.value.value in weak_algorithms

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak encryption algorithm - The configuration uses a deprecated or weak cryptographic algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    key_attributes := {"key_length", "key_size", "modulus_length", "bit_length"}
    attr.name == key_attributes[_]

    key_size := to_number(attr.value.value)
    key_size < 2048

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length - The encryption key length is too short. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    encryption_flags := {"encrypted", "enabled"}
    attr.name == encryption_flags[_]

    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled - The resource is not encrypted. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "signature_algorithm"
    attr.value.ir_type == "String"
    regex.match("(?i)sha1|md5", attr.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak signature algorithm - The certificate uses a weak signature algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "min_tls_version"
    attr.value.ir_type == "String"
    weak_tls_versions := {"TLS_1_0", "TLS_1_1"}
    attr.value.value in weak_tls_versions

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak TLS version - The minimum TLS version is set to a deprecated version. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "ssl_policy"
    attr.value.ir_type == "String"
    regex.match("(?i)ELBSecurityPolicy-TLS-1-1-2017-01|AppGwSslPolicy20150501", attr.value.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak SSL policy - The SSL policy is set to a legacy or weak version. (CWE-326)"
    }
}