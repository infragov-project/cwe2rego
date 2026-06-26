package glitch

import data.glitch_lib

weak_algo_attr_names := {
    "algorithm", "encryption_type", "cipher", "crypto_algorithm",
    "signing_algorithm", "hash_algorithm", "digest_algorithm",
    "signature_algorithm", "certificate_algorithm", "encryption_algorithm",
    "kex_algorithm", "host_key_algorithm", "mac_algorithm",
    "phase1_encryption_algorithms", "phase2_encryption_algorithms",
    "integrity_algorithm", "cipher_suite", "cipher_suites",
    "encrypt", "auth_method"
}

weak_tls_attr_names := {
    "minimum_tls_version", "ssl_version", "tls_version",
    "min_protocol_version", "ssl_policy", "security_policy",
    "tls_policy", "protocol_policy", "predefined_policy"
}

encryption_bool_attr_names := {
    "storage_encrypted", "encrypted", "enable_ssl", "enforce_https"
}

key_size_attr_names := {
    "key_size", "key_length", "key_bits", "bit_length",
    "modulus_bits", "rsa_bits", "private_key_size"
}

key_spec_attr_names := {
    "key_spec", "key_algorithm", "certificate_key_algorithm",
    "ssh_key_type", "key_type"
}

dh_group_attr_names := {"dh_group", "pfs_group"}

weak_algo_pattern := "(?i).*(\\bdes\\b|3des|triple.des|rc[245]|blowfish|md5|sha-?1\\b|hmac.sha1|_sha[^0-9]).*"

weak_tls_pattern := "(?i).*(SSLv[23]|TLSv1(\\.0|\\.1)?|TLS_1_[01]|ELBSecurityPolicy-2015).*"

weak_key_spec_pattern := "(?i).*(RSA.?1024|ECC.?192|\\bDSA\\b).*"

weak_function_name_pattern := "(?i)^(md5|sha1|des|rc4|rc2|blowfish|hmac_md5|hmac_sha1|crypt_md5|des_encrypt|sha1sum|md5sum)$"

crypto_key_name_pattern := "(?i).*(algorithm|cipher|encrypt|auth_method|key_type|key_spec|ssl|tls|hash|signing|digest|crypto).*"

var_name_crypto_pattern := "(?i).*(cipher_suite|algorithm|encrypt|signing|hash|digest|crypto|auth_method).*"

weak_in_name_pattern := "(?i).*(md5|sha.?1|\\bdes\\b|3des|rc4|rc2|blowfish).*"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_algo_attr_names[_]
    attr.value.ir_type == "String"
    regex.match(weak_algo_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected - Avoid deprecated cryptographic algorithms such as DES, RC4, MD5, SHA1. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_algo_attr_names[_]
    attr.value.ir_type == "Array"
    item := attr.value.value[_]
    item.ir_type == "String"
    regex.match(weak_algo_pattern, item.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected in list. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    regex.match(crypto_key_name_pattern, entry.key.value)
    entry.value.ir_type == "String"
    regex.match(weak_algo_pattern, entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Weak encryption algorithm in nested configuration. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, fc])
    fc.ir_type == "FunctionCall"
    regex.match(weak_function_name_pattern, fc.name)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cryptographic function used in attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, fc])
    fc.ir_type == "FunctionCall"
    arg := fc.args[_]
    arg.ir_type == "String"
    regex.match(weak_algo_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cryptographic algorithm passed as argument to function. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, access_node])
    access_node.ir_type == "Access"
    access_node.right.ir_type == "String"
    regex.match(weak_in_name_pattern, access_node.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cryptographic algorithm referenced in access key name. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(var_name_crypto_pattern, v.name)
    v.value.ir_type == "String"
    regex.match(weak_algo_pattern, v.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Weak encryption algorithm in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    walk(v.value, [_, fc])
    fc.ir_type == "FunctionCall"
    regex.match(weak_function_name_pattern, fc.name)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Weak cryptographic function in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    walk(v.value, [_, fc])
    fc.ir_type == "FunctionCall"
    arg := fc.args[_]
    arg.ir_type == "String"
    regex.match(weak_algo_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Weak cryptographic algorithm passed as argument in variable context. (CWE-326)"
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
        "description": "Insufficient encryption key length - Key size is below the recommended minimum. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == weak_tls_attr_names[_]
    attr.value.ir_type == "String"
    regex.match(weak_tls_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak TLS/SSL protocol version detected - Use TLS 1.2 or higher. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == encryption_bool_attr_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption is explicitly disabled - Always enable encryption. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == key_spec_attr_names[_]
    attr.value.ir_type == "String"
    regex.match(weak_key_spec_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak key specification detected - Use RSA >= 2048 bits, ECC >= 256 bits, and avoid DSA. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == dh_group_attr_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value <= 14
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak Diffie-Hellman group detected - Use DH group 15 or higher. (CWE-326)"
    }
}