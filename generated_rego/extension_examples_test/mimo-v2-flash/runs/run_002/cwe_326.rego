package glitch

import data.glitch_lib

weak_algo_patterns := {"(?i)\\b(des|3des|rc4|sha1|md5|ssl_v2|ssl_v3|tls_1_0|tls_1_1|http|aes-128|aes-192|rsa-512|rsa-1024|ecb|cbc)\\b"}

check_weak_string(value) {
    value.ir_type == "String"
    regex.match(weak_algo_patterns[_], value.value)
}

check_weak_function_call(node) {
    node.ir_type == "FunctionCall"
    regex.match(weak_algo_patterns[_], node.name)
} else {
    node.ir_type == "FunctionCall"
    count(node.args) > 0
    node.args[_].ir_type == "String"
    regex.match(weak_algo_patterns[_], node.args[_].value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    check_weak_string(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm used - Avoid using outdated algorithms like DES, RC4, SSLv3, etc. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    check_weak_string(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Weak encryption algorithm used - Avoid using outdated algorithms like DES, RC4, SSLv3, etc. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    check_weak_function_call(node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Weak encryption algorithm used in function call - Avoid using outdated algorithms like DES, RC4, SSLv3, etc. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    key_size_attrs := {"key_size", "key_length", "modulus_length"}
    glitch_lib.contains(attr.name, key_size_attrs[_])
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length - Key size is less than 2048 bits, which is inadequate for strong encryption. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    key_size_attrs := {"key_size", "key_length", "modulus_length"}
    glitch_lib.contains(var.name, key_size_attrs[_])
    var.value.ir_type == "Integer"
    var.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Insufficient key length - Key size is less than 2048 bits, which is inadequate for strong encryption. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    encryption_attrs := {"encryption", "enable_encryption", "server_side_encryption"}
    glitch_lib.contains(attr.name, encryption_attrs[_])
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled - Encryption is not enabled for sensitive data. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    encryption_attrs := {"encryption", "enable_encryption", "server_side_encryption"}
    glitch_lib.contains(attr.name, encryption_attrs[_])
    attr.value.ir_type == "String"
    weak_encryption_values := {"none", "false", "disabled"}
    glitch_lib.contains(attr.value.value, weak_encryption_values[_])
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption disabled - Encryption is not enabled for sensitive data. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    protocol_attrs := {"ssl_policy", "tls_version", "min_tls_version", "protocol", "cipher_suite", "ciphers"}
    glitch_lib.contains(attr.name, protocol_attrs[_])
    check_weak_string(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak protocol or cipher suite - Avoid using outdated protocols like SSLv3, TLS 1.0, or weak ciphers like DES, RC4. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    protocol_attrs := {"ssl_policy", "tls_version", "min_tls_version", "protocol", "cipher_suite", "ciphers"}
    glitch_lib.contains(var.name, protocol_attrs[_])
    check_weak_string(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Weak protocol or cipher suite - Avoid using outdated protocols like SSLv3, TLS 1.0, or weak ciphers like DES, RC4. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    key_mgmt_attrs := {"key_source", "managed_keys", "customer_managed_key", "pbkdf2_iterations", "bcrypt_cost", "rotation_interval", "enable_rotation"}
    glitch_lib.contains(attr.name, key_mgmt_attrs[_])
    attr.value.ir_type == "String"
    attr.value.value == "external"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Non-compliant key management - Weak key management settings such as external key source, no customer-managed keys, or low iteration counts. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    key_mgmt_attrs := {"key_source", "managed_keys", "customer_managed_key", "pbkdf2_iterations", "bcrypt_cost", "rotation_interval", "enable_rotation"}
    glitch_lib.contains(attr.name, key_mgmt_attrs[_])
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Non-compliant key management - Weak key management settings such as external key source, no customer-managed keys, or low iteration counts. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    key_mgmt_attrs := {"pbkdf2_iterations", "bcrypt_cost", "rotation_interval"}
    glitch_lib.contains(attr.name, key_mgmt_attrs[_])
    attr.value.ir_type == "Integer"
    glitch_lib.contains(attr.name, "pbkdf2_iterations")
    attr.value.value <= 1000
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Non-compliant key management - Weak key management settings such as external key source, no customer-managed keys, or low iteration counts. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    key_mgmt_attrs := {"pbkdf2_iterations", "bcrypt_cost", "rotation_interval"}
    glitch_lib.contains(attr.name, key_mgmt_attrs[_])
    attr.value.ir_type == "Integer"
    glitch_lib.contains(attr.name, "bcrypt_cost")
    attr.value.value <= 4
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Non-compliant key management - Weak key management settings such as external key source, no customer-managed keys, or low iteration counts. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    key_mgmt_attrs := {"pbkdf2_iterations", "bcrypt_cost", "rotation_interval"}
    glitch_lib.contains(attr.name, key_mgmt_attrs[_])
    attr.value.ir_type == "Integer"
    glitch_lib.contains(attr.name, "rotation_interval")
    attr.value.value == 0
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Non-compliant key management - Weak key management settings such as external key source, no customer-managed keys, or low iteration counts. (CWE-326)"
    }
}