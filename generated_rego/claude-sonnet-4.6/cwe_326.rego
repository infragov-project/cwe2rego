package glitch

import data.glitch_lib

weak_cipher_attr_names := {"encryption_algorithm", "cipher", "algorithm", "sse_algorithm"}

tls_version_attr_names := {"minimum_tls_version", "protocol", "tls_version", "ssl_version"}

tls_policy_attr_names := {"ssl_policy", "tls_policy", "security_policy", "security_policy_id", "predefined_policy"}

cipher_suite_attr_names := {"cipher_suite", "ciphers", "ssl_cipher", "enabled_ssl_protocols"}

hash_attr_names := {"hash_algorithm", "signing_algorithm", "digest_algorithm", "signature_algorithm", "certificate_algorithm"}

key_size_attr_names := {"key_size", "rsa_bits", "key_bits", "key_length"}

dh_group_attr_names := {"dh_group", "pfs_group"}

key_spec_attr_names := {"customer_master_key_spec", "key_algorithm", "key_type"}

ike_phase_attr_names := {"phase1_encryption", "phase2_encryption", "ike_encryption_algorithm", "esp_encryption_algorithm"}

weak_dh_group_ints := {1, 2, 5}

weak_hash_pattern := "(?i)^(MD5|SHA-?1|MD4|MD2)$"

weak_hash_receiver_pattern := "(?i)(Digest::MD5|Digest::SHA1|Digest::SHA-1|Digest::MD4|Digest::MD2|::MD5|::SHA1|::SHA-1)"

is_weak_hash_method_call(node) {
    node.ir_type == "MethodCall"
    regex.match(weak_hash_receiver_pattern, node.receiver.value)
}

is_weak_hash_filter_call(node) {
    node.ir_type == "FunctionCall"
    regex.match("(?i)(filter.*hash|hash)", node.name)
    arg := node.args[_]
    arg.ir_type == "String"
    regex.match(weak_hash_pattern, arg.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_cipher_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(DES|3DES|RC2|RC4|RC5|IDEA|Blowfish|AES-ECB|AES-CBC)$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak or broken encryption algorithm detected. Use strong algorithms like AES-256-GCM. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == key_size_attr_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient cryptographic key length. RSA/DSA keys should be at least 2048 bits. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == tls_version_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1|TLSv1|1\\.0|1\\.1|TLS_1_0|TLS_1_1)$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Deprecated TLS/SSL protocol version configured. Use TLS 1.2 or higher. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cipher_suite_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(EXPORT|NULL|ANON|RC4|DES|3DES|MD5|SHA1|SHA-1)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak or export-grade cipher suite detected. Use strong cipher suites with forward secrecy. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == hash_attr_names[_]
    attr.value.ir_type == "String"
    regex.match(weak_hash_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak or broken hash algorithm detected. Use SHA-256 or stronger for cryptographic operations. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == dh_group_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(group[_\\s-]?[125]|DHE-512|DHE-768|DHE-1024)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak Diffie-Hellman group detected. Use DH group 14 (2048-bit) or stronger. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == dh_group_attr_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value == weak_dh_group_ints[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak Diffie-Hellman group detected. Use DH group 14 (2048-bit) or stronger. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == tls_policy_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(2015|2016|TLS-1-0|TLS-1-1|TLS_1_0|TLS_1_1)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak or legacy named security policy detected. Use modern security policies with TLS 1.2 or higher. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == key_spec_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(RSA_1024|ECC_NIST_P192)", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak key specification type detected. Use RSA_2048 or stronger key specifications. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == ike_phase_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(DES|3DES|MD5|SHA1)$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak IKE/IPSec encryption algorithm detected. Use AES-256 or stronger. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "auth_method"
    attr.value.ir_type == "String"
    regex.match("(?i)^(md5|crypt)$", attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak authentication method using MD5 or DES-crypt hash. Use scram-sha-256 or stronger. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    walk(v.value, [_, node])
    is_weak_hash_method_call(node)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of weak hash algorithm (MD5/SHA1) in variable method call. Use SHA-256 or stronger. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, node])
    is_weak_hash_method_call(node)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak hash algorithm (MD5/SHA1) in attribute method call. Use SHA-256 or stronger. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, node])
    is_weak_hash_filter_call(node)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of weak hash filter (MD5/SHA1). Use SHA-256 or stronger for hashing. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, var_node])
    var_node.ir_type == "VariableReference"
    regex.match("(?i)(md5|sha1|sha-1)", var_node.value)
    walk(attr.value, [_, str_node])
    str_node.ir_type == "String"
    regex.match("(?i)(password|passwd|encrypt|crypt|auth)", str_node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Attribute references a weak hash algorithm variable in a password or encryption context. (CWE-326)"
    }
}