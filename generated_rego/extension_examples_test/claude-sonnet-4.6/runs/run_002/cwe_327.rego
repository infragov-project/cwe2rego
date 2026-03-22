package glitch

import data.glitch_lib

weak_algo_pattern := "(?i).*(RC4|\\bDES\\b|3DES|\\bMD5\\b|\\bMD4\\b|\\bSHA-?1\\b|_SHA\\b|SSLv2|SSLv3|TLSv?1\\.0|TLSv?1\\.1|TLS-1-0|TLS-1-1|\\bECB\\b|arcfour|EXPORT|\\bANON\\b|\\bADH\\b|aNULL|eNULL|\\bLOW\\b|\\bWEAK\\b|sha1WithRSA|sha1withECDSA|md5WithRSA|hmac-md5|hmac-sha1|diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|ssh-dss|3des-cbc|secp192r1|prime192v1|DES-CBC|DES-CBC3|PKCS1v1|md5_crypt|des_crypt|apr_md5_crypt).*"

crypto_name_pattern := "(?i).*(ssl_policy|security_policy|tls_policy|minimum_protocol_version|min_protocol_version|ssl_protocols|protocol_version|tls_version|cipher_suites|cipher_suite|ciphers|ssl_cipher|cipher|encryption_algorithm|algorithm|cipher_list|cipher_string|ssl_cipher_suite|allowed_ciphers|hash_algorithm|digest_algorithm|signing_algorithm|checksum_algorithm|mac_algorithm|signature_algorithm|cert_algorithm|password_hash|hash_type|hash_method|sse_algorithm|server_side_encryption|encryption_type|kex_algorithms|key_exchange|host_key_algorithms|mac_algorithms|encryption_algorithms|signature_hash_algorithm|signing_hash|key_algorithm|cipher_mode|encryption_mode|block_mode|predefined_policy|policy_name|encryption_method|ecdsa_curve|padding|encrypt|auth_method).*"

key_size_name_pattern := "(?i).*(key_size|key_length|bit_length|rsa_bits|key_bits|modulus_length|key_strength).*"

hash_fn_pattern := "(?i)(filter\\|hash|filter\\|password_hash|password_hash)"

weak_fn_name_pattern := "(?i)^(md5|sha1|md4|rc4|des)$"

sensitive_key_pattern := "(?i).*((password|passwd|secret|credential|token|hash|crypt)_(md5|sha1|sha_1|des|rc4|md4)|(md5|sha1|sha_1|des|rc4|md4)_(password|passwd|secret|credential|token|hash|crypt)).*"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(crypto_name_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(weak_algo_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak or deprecated algorithm detected in attribute. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(crypto_name_pattern, v.name)
    v.value.ir_type == "String"
    regex.match(weak_algo_pattern, v.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak or deprecated algorithm detected in variable. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    regex.match(crypto_name_pattern, entry.key.value)
    entry.value.ir_type == "String"
    regex.match(weak_algo_pattern, entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.key,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak or deprecated algorithm detected in hash entry. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, fn_node])
    fn_node.ir_type == "FunctionCall"
    regex.match(hash_fn_pattern, fn_node.name)
    arg := fn_node.args[_]
    arg.ir_type == "String"
    regex.match(weak_algo_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": fn_node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Weak hash filter function detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, fn_node])
    fn_node.ir_type == "FunctionCall"
    regex.match(weak_fn_name_pattern, fn_node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": fn_node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Direct use of weak cryptographic function. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, access_node])
    access_node.ir_type == "Access"
    access_node.right.ir_type == "String"
    regex.match(sensitive_key_pattern, access_node.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": access_node,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Field name indicates weak algorithm for sensitive data. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(key_size_name_pattern, attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value > 0
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - Insufficient cryptographic key length detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "insecure_ssl"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - SSL/TLS verification disabled. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "verify_ssl"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a broken or risky cryptographic algorithm - SSL/TLS verification disabled. (CWE-327)"
    }
}