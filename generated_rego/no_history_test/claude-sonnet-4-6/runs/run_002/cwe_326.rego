package glitch

import data.glitch_lib

weak_crypt_pattern := "(?i)(3des|tdea|rc2|rc4|rc5|idea|skipjack|blowfish|md5|sha1|sha-1|sha_1|md4|md2|rsa.?1024|dsa.?1024|pbkdf1|SSLv2|SSLv3|TLSv1\\.0|TLSv1\\.1|TLS1_0|TLS1_1|_CBC_SHA\\b)"

algo_name_pattern := "(?i)(algorithm|encryption_algorithm|cipher_suites|cipher_suite|cipher|signing_algorithm|digest_algorithm|hashing_algorithm|kms_key_spec|key_algorithm|key_spec|key_type|ssl_policy|tls_policy|minimum_tls_version|tls_min_version|ssl_protocols|enabled_protocols|accepted_protocols|ssl_cipher_suite|cipher_policy|auth_method|encrypt|encryption_method|kdf|key_derivation)"

key_size_name_pattern := "(?i)(key_size|key_length|rsa_bits|bit_length|key_bits|modulus_length|aes_bits|encryption_key_length)"

weak_crypto_func_pattern := "(?i)^(md5|sha1|sha_1|sha-1|md4|md2|des|3des|rc4|rc2|blowfish|pbkdf1)$"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(algo_name_pattern, attr.name)
    attr.value.ir_type == "String"
    regex.match(weak_crypt_pattern, attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or deprecated encryption algorithm detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    regex.match(algo_name_pattern, v.name)
    v.value.ir_type == "String"
    regex.match(weak_crypt_pattern, v.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak or deprecated encryption algorithm in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(algo_name_pattern, attr.name)
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    regex.match(weak_crypt_pattern, elem.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak protocol or cipher in list. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(key_size_name_pattern, attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value <= 1024
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Key size is too small. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "FunctionCall"
    regex.match(weak_crypto_func_pattern, attr.value.name)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Use of weak cryptographic function. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    v.value.ir_type == "FunctionCall"
    regex.match(weak_crypto_func_pattern, v.value.name)
    result := {
        "type": "sec_weak_crypt",
        "element": v,
        "path": parent.path,
        "description": "Inadequate encryption strength - Use of weak cryptographic function in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    kv.key.ir_type == "String"
    regex.match(algo_name_pattern, kv.key.value)
    kv.value.ir_type == "String"
    regex.match(weak_crypt_pattern, kv.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": kv.value,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak encryption in nested configuration. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr, [_, node])
    node.ir_type == "FunctionCall"
    arg := node.args[_]
    arg.ir_type == "String"
    regex.match(weak_crypt_pattern, arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic algorithm used as function argument. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr, [_, node])
    node.ir_type == "Access"
    node.right.ir_type == "String"
    regex.match(weak_crypt_pattern, node.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate encryption strength - Weak cryptographic reference in data access. (CWE-326)"
    }
}