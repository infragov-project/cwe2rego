package glitch

import data.glitch_lib

crypto_attr_pattern := "(?i).*(\\balgorithm|encrypt|cipher|ssl_policy|security_policy|tls_version|min_tls|minimum_protocol|ssl_protocol|protocol_version|hash_alg|digest|signing|signature|integrity_alg|mac_alg|\\bhmac\\b|cipher_mode|block_mode|ike_encrypt|ipsec_encrypt|dh_group|kex|host_key|mac_algorithms|\\bciphers\\b|sse_alg|kms_alg|key_alg|encryption_type|server_side_encrypt|disk_encrypt|key_type|predefined_policy|negotiation_policy|auth_method|auth_alg).*"

weak_algo_pattern := "(?i).*(\\bDES\\b|\\b3DES\\b|\\bRC2\\b|\\bRC4\\b|\\bRC5\\b|\\bECB\\b|\\bMD4\\b|md5|sha-?1\\b|RIPEMD160|SSLv[23]|TLSv1\\.[01]|TLS_1_[01]|\\bGroup[125]\\b|arcfour|blowfish-cbc|3des-cbc|hmac-md5|hmac-sha1|SHA1withRSA|MD5withRSA|RSA1024|DSA1024|diffie-hellman-group1|CBC[-_]SHA).*"

key_size_attr_pattern := "(?i).*(key_size|key_length|rsa_bits|key_bits|modulus_length|dh_param_bits|ec_bits|bit_strength).*"

weak_key_sizes := {512, 768, 1024}

value_has_weak_string(value) {
    walk(value, [_, node])
    node.ir_type == "String"
    regex.match(weak_algo_pattern, node.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(crypto_attr_pattern, attr.name)
    value_has_weak_string(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak or deprecated cryptographic algorithm detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(crypto_attr_pattern, v.name)
    value_has_weak_string(v.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak or deprecated cryptographic algorithm detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    regex.match(crypto_attr_pattern, entry.key.value)
    entry.value.ir_type == "String"
    regex.match(weak_algo_pattern, entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak algorithm in nested configuration. (CWE-327)"
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
    regex.match(weak_algo_pattern, access_node.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak algorithm referenced in access expression. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(key_size_attr_pattern, attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value == weak_key_sizes[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Insufficient cryptographic key size detected. (CWE-327)"
    }
}