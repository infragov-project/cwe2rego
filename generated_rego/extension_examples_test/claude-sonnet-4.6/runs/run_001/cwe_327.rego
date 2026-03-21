package glitch

import data.glitch_lib

crypto_name_pattern := "(?i).*(ssl_policy|security_policy|tls_policy|protocol_version|min_protocol_version|minimum_tls_version|cipher_suite|cipher_suites|allowed_ciphers|encryption_algorithm|cipher|ciphers|hash_algorithm|digest_algorithm|signing_algorithm|signature_algorithm|hash_type|hmac_algorithm|integrity_algorithm|auth_algorithm|auth_method|encrypt|encryption_type|algorithm|sse_algorithm|kms_key_algorithm|block_cipher|cipher_mode|encryption_mode|ike_versions|dh_group|pfs_group|key_exchange|certificate_algorithm|private_key_algorithm|key_algorithm|phase1_encryption_algorithms|phase2_encryption_algorithms|phase1_integrity_algorithms|phase2_integrity_algorithms|encryption_algorithms).*"

weak_crypto_str_pattern := "(?i).*(SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1|TLS1\\.0|TLS1\\.1|ELBSecurityPolicy-2015|ELBSecurityPolicy-TLS-1-0|3DES|TDES|RC4|RC2|\\bDES\\b|MD5|SHA-1|SHA1|MD4|MD2|CRC32|Blowfish|AES-ECB|IKEv1|DH_GROUP_1|DH_GROUP_2|DH_GROUP_5|modp768|modp1024|SHA1withRSA|MD5withRSA|RSA_1024|DSA_1024|_CBC_SHA(?:[^0-9]|$)).*"

weak_algo_func_pattern := "(?i)^(md5|sha1|sha_1|sha-1|md4|md2|crc32)$"

hash_func_name_pattern := "(?i).*(hash|digest|hmac).*"

weak_algo_arg_pattern := "(?i)^(md5|sha1|sha-1|sha_1|md4|md2|crc32|rc4|des|3des|tdes|rc2|blowfish|ecb)$"

weak_in_key_pattern := "(?i).*(_md5|_sha1|_sha-1|md5_|sha1_).*"

enc_state_pattern := "(?i).*(encryption_enabled|encrypted|storage_encrypted|enable_encryption|in_transit_encryption|at_rest_encryption).*"

key_size_pattern := "(?i).*(key_size|key_length|bit_size|rsa_bits|key_bits|modulus_size|ec_bits).*"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(crypto_name_pattern, attr.name)
    walk(attr.value, [_, str_node])
    str_node.ir_type == "String"
    regex.match(weak_crypto_str_pattern, str_node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(crypto_name_pattern, v.name)
    walk(v.value, [_, str_node])
    str_node.ir_type == "String"
    regex.match(weak_crypto_str_pattern, str_node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm in variable. (CWE-327)"
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
    walk(entry.value, [_, str_node])
    str_node.ir_type == "String"
    regex.match(weak_crypto_str_pattern, str_node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.key,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm in hash configuration entry. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, func_node])
    func_node.ir_type == "FunctionCall"
    regex.match(weak_algo_func_pattern, func_node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": func_node,
        "path": parent.path,
        "description": "Direct use of weak cryptographic hash function. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, func_node])
    func_node.ir_type == "FunctionCall"
    regex.match(hash_func_name_pattern, func_node.name)
    arg := func_node.args[_]
    arg.ir_type == "String"
    regex.match(weak_algo_arg_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": func_node,
        "path": parent.path,
        "description": "Use of weak algorithm in hash function call. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, access_node])
    access_node.ir_type == "Access"
    access_node.right.ir_type == "String"
    regex.match(weak_in_key_pattern, access_node.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": access_node,
        "path": parent.path,
        "description": "Weak cryptographic algorithm referenced in key or field name. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(enc_state_pattern, attr.name)
    glitch_lib.traverse(attr.value, false)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Encryption is explicitly disabled. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(key_size_pattern, attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient cryptographic key size. (CWE-327)"
    }
}