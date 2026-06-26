package glitch

import data.glitch_lib

weak_crypto_field_name(name) {
    regex.match("(?i).*(ssl_policy|security_policy|minimum_tls|min_protocol|tls_version|ssl_protocol|protocol_version|https_protocol|cipher_suite|ciphers|cipher_list|cipher_algo|encryption_cipher|hash_algo|hashing_algo|digest_algo|integrity_algo|checksum_algo|mac_algo|signing_algo|signature_algo|cert_algo|hash_function|encryption_algo|kms_key_algo|key_algo|storage_encryption|encryption_type|server_side_encrypt|ike_encrypt|ipsec_encrypt|dh_group|pfs_group|tls_policy|cipher_policy|negotiation_policy|policy_name|auth_method|auth_algo|authentication_method|auth_type|encrypt).*", name)
}

weak_algo_value(v) {
    regex.match("(?i).*(md2|md4|md5|sha-?1\\b|sha_1\\b|\\bsha1\\b|_sha\\b|ripemd.?128|hmac.?md5|\\bdes\\b|3des|triple.?des|\\brc4\\b|\\brc2\\b|arcfour|blowfish|\\bnull\\b|\\bexport\\b|\\banon\\b|\\bidea\\b|\\bseed\\b|sslv?2|sslv?3|ssl3|tlsv?1[_.]?0|tlsv?1[_.]?1|tls1[_.]?0|tls1[_.]?1|group[125]\\b|modp768|modp1024|\\becb\\b|\\blegacy\\b|ELBSecurityPolicy-TLS-1-0|ELBSecurityPolicy-201[0-8]).*", v)
}

weak_algo_in_subtree(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    weak_algo_value(n.value)
}

weak_crypto_in_func(node) {
    walk(node, [_, n])
    n.ir_type == "FunctionCall"
    regex.match("(?i)^(md2|md4|md5|sha1|sha_1|3des|des|rc2|rc4|blowfish|arcfour|hmac_md5|hmacmd5)$", n.name)
}

weak_crypto_in_func(node) {
    walk(node, [_, n])
    n.ir_type == "FunctionCall"
    regex.match("(?i).*(hash|digest|hmac|encrypt|cipher|checksum).*", n.name)
    arg := n.args[_]
    arg.ir_type == "String"
    weak_algo_value(arg.value)
}

weak_algo_in_access_key(node) {
    walk(node, [_, n])
    n.ir_type == "Access"
    n.right.ir_type == "String"
    weak_algo_value(n.right.value)
}

is_kv_node(node) {
    node.ir_type == "Attribute"
}

is_kv_node(node) {
    node.ir_type == "Variable"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    is_kv_node(kv)
    weak_crypto_field_name(kv.name)
    weak_algo_in_subtree(kv.value)
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    is_kv_node(kv)
    weak_crypto_in_func(kv.value)
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm in function call. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    is_kv_node(kv)
    weak_algo_in_access_key(kv.value)
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm referenced in access key. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    weak_crypto_field_name(entry.key.value)
    weak_algo_in_subtree(entry.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm in hash entry. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    is_kv_node(kv)
    regex.match("(?i).*(encryption_enabled|enforce_https|require_secure_transport|ssl_enforcement|tls_enabled|in_transit_encryption|require_ssl).*", kv.name)
    kv.value.ir_type == "Boolean"
    kv.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Encryption enforcement is disabled. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    is_kv_node(kv)
    regex.match("(?i).*(key_size|key_length|rsa_bits|key_bits|modulus_size|dsa_bits).*", kv.name)
    kv.value.ir_type == "Integer"
    kv.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Insufficient cryptographic key length detected. (CWE-327)"
    }
}