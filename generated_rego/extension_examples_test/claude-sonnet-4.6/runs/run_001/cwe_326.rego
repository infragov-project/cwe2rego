package glitch

import data.glitch_lib

weak_algo_val_p := "(?i)^(des|3des|tripledes|rc2|rc4|rc5|blowfish|md5|sha-?1|sha1|sha_1|sha1_crypt|md5_crypt|des_crypt|null|export|anon|sha1withrsa|md5withrsa|rsa_512|rsa_1024)$"

weak_cipher_val_p := "(?i).*(_SHA\\b|\\bNULL\\b|EXPORT|\\bRC4\\b|\\bDES\\b|\\b3DES\\b|\\bMD5\\b|\\bADH\\b|\\bAECDH\\b|\\banon\\b).*"

weak_tls_val_p := "(?i).*(sslv2|sslv3|tlsv?1\\.0|tlsv?1\\.1|tls_1_0|tls_1_1).*"

algo_name_p := "(?i).*(\\balgorithm\\b|encryption_algorithm|key_algorithm|signing_algorithm|\\bcipher\\b|ssl_cipher|tls_cipher|key_type|key_spec|private_key_type|certificate_algorithm|digest_algorithm|hash_algorithm|encryption_type|\\bencrypt\\b|auth_method).*"

cipher_name_p := "(?i).*(cipher_suite|cipher_list|ssl_ciphers|tls_ciphers|allowed_cipher|preferred_cipher).*"

tls_name_p := "(?i).*(minimum_tls_version|min_tls_version|tls_version|ssl_policy|tls_policy|tls_security_policy|security_policy|ssl_protocol|enabled_ssl_protocols).*"

key_size_name_p := "(?i).*(rsa_bits|key_bits|key_size|key_length|bit_length|modulus_size|key_strength).*"

enc_name_p := "(?i)^(encrypted|storage_encrypted|enable_encryption|encryption_enabled|at_rest_encryption|in_transit_encryption)$"

weak_hash_func_p := "(?i)^(md5|sha1|sha_1|des|rc4|rc2|blowfish)$"

weak_hash_arg_p := "(?i)^(md5|sha-?1|sha1|sha_1|md5_crypt|sha1_crypt|des_crypt|blowfish_crypt)$"

security_attr_p := "(?i).*(password|passphrase|secret|credential|token).*"

weak_algo_key_p := "(?i).*(md5|sha1|sha_1|\\bdes\\b|\\b3des\\b|rc4).*"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    glitch_lib.is_ir_type_in(n, {"Attribute", "Variable"})
    regex.match(algo_name_p, n.name)
    n.value.ir_type == "String"
    regex.match(weak_algo_val_p, n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak or deprecated encryption algorithm detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    glitch_lib.is_ir_type_in(n, {"Attribute", "Variable"})
    regex.match(cipher_name_p, n.name)
    n.value.ir_type == "String"
    regex.match(weak_cipher_val_p, n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Weak cipher suite detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    glitch_lib.is_ir_type_in(n, {"Attribute", "Variable"})
    regex.match(tls_name_p, n.name)
    n.value.ir_type == "String"
    regex.match(weak_tls_val_p, n.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Outdated TLS/SSL protocol version detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Attribute"
    regex.match(enc_name_p, n.name)
    n.value.ir_type == "Boolean"
    n.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Encryption explicitly disabled. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Attribute"
    regex.match(key_size_name_p, n.name)
    n.value.ir_type == "Integer"
    n.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Insufficient key size for encryption. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, h])
    h.ir_type == "Hash"
    entry := h.value[_]
    entry.key.ir_type == "String"
    regex.match(algo_name_p, entry.key.value)
    entry.value.ir_type == "String"
    regex.match(weak_algo_val_p, entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Weak algorithm specified in configuration block. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, fc])
    fc.ir_type == "FunctionCall"
    regex.match("(?i).*(hash|digest|crypt).*", fc.name)
    arg := fc.args[_]
    arg.ir_type == "String"
    regex.match(weak_hash_arg_p, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": fc,
        "path": parent.path,
        "description": "Weak hash algorithm used in function call. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, fc])
    fc.ir_type == "FunctionCall"
    regex.match(weak_hash_func_p, fc.name)
    result := {
        "type": "sec_weak_crypt",
        "element": fc,
        "path": parent.path,
        "description": "Direct call to weak hash or encryption function. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, n])
    n.ir_type == "Attribute"
    regex.match(security_attr_p, n.name)
    walk(n.value, [_, acc])
    acc.ir_type == "Access"
    acc.right.ir_type == "String"
    regex.match(weak_algo_key_p, acc.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": n,
        "path": parent.path,
        "description": "Security attribute accesses a field with a weak algorithm indicator. (CWE-326)"
    }
}