package glitch

import data.glitch_lib

weak_cipher_pattern := "(?i)(^(des|3des|tdes|rc[2-5]|idea|blowfish|des-cbc|des-ede|rc4-md5|rc4-sha|null|none|exp-.*)$|_cbc_sha([^0-9]|$)|_with_rc4_|_with_des_|_with_3des_)"

weak_hash_pattern := "(?i)^(md[2-5]|sha-?1|hmac-md5|hmac-sha1|sha1withrsa.*|md5withrsa.*|des_crypt|md5_crypt|md5crypt|crypt)$"

weak_hash_func_name_pattern := "(?i)^(md[2-5]|sha-?1|hmac.?md5|hmac.?sha1|crypt|des.?crypt|md5crypt)$"

weak_tls_pattern := "(?i)(^sslv?[23]$|^ssl[23]$|^tlsv?1(\\.0|\\.1)?$|tls.?1[_-]0|tls.?1[_-]1)"

cipher_attr_pattern := "(?i)(encryption_algorithm|cipher_suites?|^algorithm$|encryption_type|cipher_mode|block_cipher_mode|encryption_mode|sse_algorithm|server_side_encryption|vpn_cipher|tunnel_encryption)"

hash_attr_pattern := "(?i)(hash_algorithm|hashing_algorithm|integrity_algorithm|digest_algorithm|checksum_algorithm|hmac_algorithm|message_digest|signature_algorithm|auth_algorithm|auth_method|signing_algorithm|cert_algorithm|password_hashing_algorithm|hash_function|password_algorithm|encrypt)"

tls_attr_pattern := "(?i)(minimum_tls_version|min_tls_version|ssl_policy|tls_policy|protocol_version|ssl_protocols|tls_protocols|enabled_protocols|security_policy)"

key_size_attr_pattern := "(?i)(key_size|key_length|key_bits|rsa_bits|modulus_length|dh_param_size)"

enforce_false_pattern := "(?i)(enforce_https|require_https|verify_ssl|ssl_verify|tls_verify|require_encryption)"

insecure_true_pattern := "(?i)(insecure_ssl|disable_ssl_validation|skip_tls_verification|allow_unencrypted_traffic|allow_ssl)"

weak_alg_substr_pattern := "(?i).*(md[2-5]|sha-?1|des|rc4|3des|blowfish).*"

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
        "description": "Use of a broken or risky cryptographic algorithm - Weak or deprecated cipher detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(hash_attr_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(weak_hash_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak or deprecated hash algorithm detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "FunctionCall"
    regex.match(weak_hash_func_name_pattern, attr.value.name)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak hash function called in attribute. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    v.value.ir_type == "FunctionCall"
    regex.match(weak_hash_func_name_pattern, v.value.name)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak hash function called in variable. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "FunctionCall"
    regex.match("(?i)(hash|digest|crypt|hmac)", attr.value.name)
    arg := attr.value.args[_]
    arg.ir_type == "String"
    regex.match(weak_hash_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak hash function call detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Access"
    attr.value.right.ir_type == "String"
    regex.match(weak_alg_substr_pattern, attr.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak hash algorithm referenced in attribute access. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, hnode])
    hnode.ir_type == "Hash"
    entry := hnode.value[_]
    entry.key.ir_type == "String"
    regex.match(hash_attr_pattern, entry.key.value)
    entry.value.ir_type == "String"
    regex.match(weak_hash_pattern, entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.key,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak hash algorithm in nested configuration. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, hnode])
    hnode.ir_type == "Hash"
    entry := hnode.value[_]
    entry.key.ir_type == "String"
    regex.match(cipher_attr_pattern, entry.key.value)
    entry.value.ir_type == "String"
    regex.match(weak_cipher_pattern, entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.key,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak cipher in nested configuration. (CWE-327)"
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
        "description": "Use of a broken or risky cryptographic algorithm - Weak cipher in variable configuration. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(hash_attr_pattern, v.name)
    v.value.ir_type == "String"
    regex.match(weak_hash_pattern, v.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak hash algorithm in variable configuration. (CWE-327)"
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
        "description": "Use of a broken or risky cryptographic algorithm - Insecure TLS/SSL protocol version enabled. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(key_size_attr_pattern, attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Cryptographic key size is too small. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(enforce_false_pattern, attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Encryption or SSL/TLS verification enforcement is disabled. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(insecure_true_pattern, attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Insecure SSL/TLS bypass flag is enabled. (CWE-327)"
    }
}