package glitch

import data.glitch_lib

weak_algorithms := {"des", "3des", "rc4", "aes-128", "blowfish", "sha1", "md5", "rsa-1024", "ecdsa-160", "ssh-rsa", "tls_1.0", "tls_1.1", "ssl", "sslv2", "sslv3", "md5_crypt"}
weak_key_lengths := {1024, 128, 160, 56, 112}
encryption_keywords := {"algorithm", "cipher", "encryption_algorithm", "key_algorithm", "encryption_type", "encrypt", "hash", "digest", "cipher_suites"}
protocol_keywords := {"protocol", "tls_version", "ssl_policy", "cipher_suite", "min_tls_version"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    encryption_keywords[attr.name]
    attr.value.ir_type == "String"
    attr.value.value in weak_algorithms
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of deprecated or weak encryption algorithm (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    encryption_keywords[attr.name]
    attr.value.ir_type == "Integer"
    attr.value.value in weak_key_lengths
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length for encryption (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    protocol_keywords[attr.name]
    glitch_lib.traverse(attr.value, weak_algorithms)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak protocol or TLS version (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    not (encryption_keywords[attr.name] or protocol_keywords[attr.name])
    glitch_lib.traverse(attr.value, weak_algorithms)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of deprecated or weak encryption algorithm (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    encryption_keywords[var.name]
    var.value.ir_type == "String"
    var.value.value in weak_algorithms
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of deprecated or weak encryption algorithm (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    encryption_keywords[var.name]
    var.value.ir_type == "Integer"
    var.value.value in weak_key_lengths
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Insufficient key length for encryption (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    protocol_keywords[var.name]
    glitch_lib.traverse(var.value, weak_algorithms)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of weak protocol or TLS version (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    not (encryption_keywords[var.name] or protocol_keywords[var.name])
    glitch_lib.traverse(var.value, weak_algorithms)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of deprecated or weak encryption algorithm (CWE-326)"
    }
}