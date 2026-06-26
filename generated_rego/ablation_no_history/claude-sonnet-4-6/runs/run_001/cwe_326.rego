package glitch

import data.glitch_lib

weak_algo_pattern := "(?i).*(DES|3DES|TRIPLE_DES|RC2|RC4|ARCFOUR|Blowfish|IDEA|RSA_1024|MD5|SHA-?1).*"

weak_cipher_pattern := "(?i).*(NULL|EXPORT|_RC4_|_DES_|_3DES_|ANON|_MD5|_SHA\\b).*"

weak_tls_pattern := "(?i).*(SSLv2|SSLv3|SSL2|SSL3|TLSv1\\.0|TLSv1\\.1|TLS1_0|TLS1_1|TLS_1_0|TLS_1_1).*"

legacy_policy_pattern := "(?i).*(2014|2015|2016|Legacy|Deprecated|TLS-1-0|TLS-1-1|FS-1-0).*"

algo_attr_name_pattern := "(?i).*(algorithm|cipher|encryption|auth|hash|digest|key_spec|key_type|crypto|encrypt).*"

cipher_attr_pattern := "(?i).*(cipher|tls|ssl).*"

tls_attr_pattern := "(?i).*(tls_version|ssl_version|min_tls|protocol).*"

weak_func_name_pattern := "(?i)^(md5|sha1|sha_1|des|rc4|rc2|blowfish|arcfour)$"

policy_attr_names := {"ssl_policy", "security_policy", "predefined_policy", "listener_policy"}

encryption_flag_names := {"encrypted", "storage_encrypted", "enable_encryption", "encryption_at_rest"}

key_size_names := {"key_size", "key_length", "bit_length", "key_bits", "rsa_bits"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(algo_attr_name_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(weak_algo_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cryptographic algorithm detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(algo_attr_name_pattern, v.name)
    v.value.ir_type == "String"
    regex.match(weak_algo_pattern, v.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Weak cryptographic algorithm in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(cipher_attr_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(weak_cipher_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cipher suite configured. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(cipher_attr_pattern, v.name)
    v.value.ir_type == "String"
    regex.match(weak_cipher_pattern, v.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Weak cipher suite in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(tls_attr_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(weak_tls_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak TLS/SSL protocol version configured. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == policy_attr_names[_]
    attr.value.ir_type == "String"
    regex.match(legacy_policy_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Legacy or permissive security policy detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == encryption_flag_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption is explicitly disabled. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == key_size_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient cryptographic key size. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, fc])
    fc.ir_type == "FunctionCall"
    regex.match(weak_func_name_pattern, fc.name)
    result := {
        "type": "sec_weak_crypt",
        "element": fc,
        "path": parent.path,
        "description": "Use of weak cryptographic function. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, fc])
    fc.ir_type == "FunctionCall"
    arg := fc.args[_]
    arg.ir_type == "String"
    regex.match(weak_algo_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": fc,
        "path": parent.path,
        "description": "Use of weak cryptographic algorithm as function argument. (CWE-326)"
    }
}