package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC4", "AES-128", "RSA-1024", "DSA-1024", "ECDSA-160", "SHA-1", "MD5"}
key_length_attrs := {"key_length", "key_size", "key_spec", "bit_length"}
weak_protocols := {"SSLv3", "TLSv1.0", "TLSv1.1"}
protocol_attrs := {"protocol", "ssl_policy", "min_tls_version", "tls_version", "ssl_protocol"}
cipher_attrs := {"ciphers", "cipher_suites", "security_policy", "ssl_cipher_suite"}
weak_ciphers := {"3DES", "RC4", "DES", "CBC", "NULL", "EXPORT"}
insecure_config_attrs := {"encryption_enabled", "enable_encryption", "encryption_option", "kms", "server_side_encryption"}
insecure_values := {"false", "disabled", "none"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    attr.name == algorithm_attrs[_]
    attr.value.value == weak_algorithms[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected - Using inadequate encryption algorithms (e.g., DES, 3DES, RC4) can lead to security vulnerabilities. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == key_length_attrs[_]
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length detected - Key length is too short and may be vulnerable to brute force attacks. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == protocol_attrs[_]
    attr.value.ir_type == "String"
    attr.value.value == weak_protocols[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Outdated TLS/SSL protocol detected - Using deprecated protocols (e.g., SSLv3, TLSv1.0, TLSv1.1) can lead to security vulnerabilities. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == protocol_attrs[_]
    attr.value.ir_type == "String"
    regex.match(".*2016.*", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Outdated TLS/SSL protocol detected - Using deprecated policies containing 2016 or earlier can lead to security vulnerabilities. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == cipher_attrs[_]
    attr.value.ir_type == "String"
    attr.value.value == weak_ciphers[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cipher suite detected - Using weak cipher suites (e.g., 3DES, RC4, DES, CBC, NULL, EXPORT) can lead to security vulnerabilities. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == insecure_config_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure default configuration detected - Encryption is disabled, which may lead to data exposure. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == insecure_config_attrs[_]
    attr.value.ir_type == "String"
    attr.value.value == insecure_values[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insecure default configuration detected - Encryption is disabled or not enabled, which may lead to data exposure. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    key := kv.key
    value := kv.value
    value.ir_type == "String"
    key.ir_type == "String"
    key.value == "security_policy"
    regex.match(".*2016.*", value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Outdated TLS/SSL protocol detected - Using deprecated policies containing 2016 or earlier can lead to security vulnerabilities. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    key := kv.key
    value := kv.value
    value.ir_type == "String"
    key.ir_type == "VariableReference"
    key.value == ":ssl_protocol"
    value.value == "TLSv1.0"
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Outdated TLS/SSL protocol detected - Using deprecated protocols (e.g., TLSv1.0) can lead to security vulnerabilities. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    key := kv.key
    value := kv.value
    value.ir_type == "String"
    key.ir_type == "VariableReference"
    key.value == ":ssl_cipher_suite"
    regex.match(".*HIGH.*", value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Weak cipher suite detected - Using weak cipher suites can lead to security vulnerabilities. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "ssl_ciphers"
    attr.value.ir_type == "String"
    attr.value.value == "RC4-SHA:DES-CBC3-SHA:AES128-SHA"
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cipher suite detected - Using weak cipher suites (e.g., RC4, 3DES) can lead to security vulnerabilities. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "ssl_protocol"
    attr.value.ir_type == "String"
    regex.match(".*TLSv1.*", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Outdated TLS/SSL protocol detected - Using deprecated protocols (e.g., TLSv1) can lead to security vulnerabilities. (CWE-326)"
    }
}