package glitch

import data.glitch_lib

weak_algorithms := {"des", "3des", "triple-des", "rc4", "aes128", "rsa1024", "sha1", "md5", "blowfish", "aes-128-cbc", "DES", "AES128", "AES128-SHA"}
weak_protocols := {"ssl_v2", "ssl_v3", "tls_1_0", "tls_1_1", "tls1", "tls1.1", "tls_v1", "tls_v1.1", "TLSv1", "TLSv1.1", "SSLv3"}
weak_key_sizes := {56, 64, 128, 1024}
secret_names := {"secret", "key", "password", "token", "db_encryption_key", "encryption_key"}
protocol_attributes := {"protocol_version", "ssl_policy", "tls_version", "min_protocol_version", "cipher_suite", "ssl_protocols"}
key_size_attributes := {"key_size", "key_length", "key_bits", "rsa_key_size"}
encryption_attributes := {"algorithm", "kms_algorithm", "encryption_algorithm", "cipher", "crypto_algorithm", "encryption_method"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    protocol_attributes[entry.key.value]
    entry.value.ir_type == "String"
    weak_protocol := weak_protocols[_]
    glitch_lib.contains(entry.value.value, weak_protocol)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of outdated protocol - Avoid using deprecated protocols. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    protocol_attributes[attr.name]
    attr.value.ir_type == "String"
    weak_protocol := weak_protocols[_]
    glitch_lib.contains(attr.value.value, weak_protocol)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of outdated protocol - Avoid using deprecated protocols. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, n])
    n.ir_type == "String"
    weak_algorithm := weak_algorithms[_]
    glitch_lib.contains(n.value, weak_algorithm)
    not secure_cipher_suite(n.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Use of weak encryption algorithm - Avoid using deprecated or broken algorithms. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    encryption_attributes[attr.name]
    attr.value.ir_type == "String"
    weak_algorithm := weak_algorithms[_]
    glitch_lib.contains(attr.value.value, weak_algorithm)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak encryption algorithm - Avoid using deprecated or broken algorithms. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    key_size_attributes[attr.name]
    attr.value.ir_type == "Integer"
    weak_key_sizes[attr.value.value]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key size - Key size is too small for modern encryption. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "Integer"
    weak_key_sizes[var.value.value]
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Insufficient key size - Key size is too small for modern encryption. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "String"
    weak_protocol := weak_protocols[_]
    glitch_lib.contains(var.value.value, weak_protocol)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of outdated protocol - Avoid using deprecated protocols. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "String"
    secret_name := secret_names[_]
    glitch_lib.contains(var.name, secret_name)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Hardcoded secret - Avoid hardcoding secrets in IaC scripts. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    secret_name := secret_names[_]
    glitch_lib.contains(attr.value.value, secret_name)
    attr.name != "path"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded secret - Avoid hardcoding secrets in IaC scripts. (CWE-326)"
    }
}

secure_cipher_suite(s) {
    glitch_lib.contains(s, "HIGH")
    glitch_lib.contains(s, "!aNULL")
}