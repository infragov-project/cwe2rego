package glitch

import data.glitch_lib

weak_algo_pattern := "(?i).*(\\b3DES\\b|\\bTDEA\\b|\\bRC2\\b|\\bRC4\\b|\\bRC5\\b|\\bBlowfish\\b|\\bIDEA\\b|\\bMD5\\b|SHA-1|\\bSHA1\\b|\\bCRC32\\b|HMAC-MD5|HMAC-SHA1|SHA1withRSA|MD5withRSA|RSA_1024|RSA_512|DSA_1024|\\bDES\\b|_SHA[^0-9a-zA-Z]).*"

weak_tls_pattern := "(?i).*(SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1|ELBSecurityPolicy-2015|ELBSecurityPolicy-TLS-1-0|ELBSecurityPolicy-TLS-1-1|WITH_RC4|WITH_DES|WITH_3DES|_EXPORT_|_NULL_).*"

weak_func_pattern := "(?i)^(md5|sha1|sha_1|crc32|hmac_md5|hmac_sha1|des_encrypt|rc4_encrypt)$"

crypto_field_pattern := "(?i).*(algorithm|cipher|sse_algorithm|encryption_type|server_side_encryption|hash_algorithm|hash_function|digest_algorithm|signing_algorithm|key_algorithm|hmac_algorithm|ssl_policy|security_policy|protocol_policy|minimum_protocol_version|min_protocol_version|ssl_protocol|tls_version|cipher_suite|allowed_cipher|ssl_cipher|auth_method).*"

string_is_weak(str) {
    regex.match(weak_algo_pattern, str)
}

string_is_weak(str) {
    regex.match(weak_tls_pattern, str)
}

value_contains_weak(value) {
    walk(value, [_, node])
    node.ir_type == "String"
    string_is_weak(node.value)
}

value_contains_weak(value) {
    walk(value, [_, node])
    node.ir_type == "FunctionCall"
    regex.match(weak_func_pattern, node.name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    kv.ir_type == "Attribute"
    regex.match(crypto_field_pattern, kv.name)
    value_contains_weak(kv.value)
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Weak or deprecated encryption algorithm detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    kv.ir_type == "Variable"
    regex.match(crypto_field_pattern, kv.name)
    value_contains_weak(kv.value)
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Weak or deprecated encryption algorithm detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    kv.ir_type == "Variable"
    walk(kv.value, [_, fn_node])
    fn_node.ir_type == "FunctionCall"
    regex.match(weak_func_pattern, fn_node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Weak cryptographic function call detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    kv_pair := hash_node.value[_]
    kv_pair.key.ir_type == "String"
    regex.match(crypto_field_pattern, kv_pair.key.value)
    kv_pair.value.ir_type == "String"
    string_is_weak(kv_pair.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": kv_pair.value,
        "path": parent.path,
        "description": "Weak or deprecated encryption algorithm in hash configuration. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    kv.ir_type == "Attribute"
    kv.value.ir_type == "Integer"
    regex.match("(?i)^(key_size|key_length|key_bits|bit_length|modulus_length|rsa_bits|dsa_bits)$", kv.name)
    kv.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Insufficient RSA/DSA key length - Use at least 2048 bits. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    kv.ir_type == "Attribute"
    kv.value.ir_type == "Integer"
    regex.match("(?i)^ecdsa_bits$", kv.name)
    kv.value.value < 224
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Insufficient ECC key length - Use at least 224 bits. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    kv.ir_type == "Attribute"
    kv.value.ir_type == "Boolean"
    kv.value.value == false
    regex.match("(?i)^(storage_encrypted|encrypted|require_secure_transport|enforce_https|https_only|fips_enabled)$", kv.name)
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": "Encryption or secure transport enforcement is disabled. (CWE-326)"
    }
}