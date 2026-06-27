package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC2", "RC4", "BLOWFISH", "MD5", "SHA1", "SHA-1", "PBKDF1", "HMAC-MD5", "HMAC-SHA1", "MD5withRSA", "SHA1withRSA", "SHA_1", "MD5_"}
weak_tls_versions := {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "1.0", "1.1", "TLS-1.0", "TLS-1-1", "TLS-1.0-2010", "TLS-1-1-2017"}
weak_ssl_policies := {"COMPATIBILITY", "LEGACY", "WEAK", "COMPATIBLE", "ELBSecurityPolicy-TLS-1-0", "ELBSecurityPolicy-TLS-1-1"}
encryption_attr_names := {"algorithm", "cipher", "encryption", "encrypt", "type", "hash_algorithm", "digest", "kdf", "key_derivation", "mac", "hmac", "signature_algorithm", "kms_key_spec", "key_spec", "tls_version", "min_version", "ssl_policy", "tls_policy", "policy", "sse_algorithm", "iterations", "iteration_count", "salt_length", "key_size", "key_length", "key_bits", "rsa_key_size", "modulus_size", "elliptic_curve", "cipher_suites", "ciphers"}
storage_encryption_names := {"storage_encrypted", "encryption_at_rest", "rotation"}
auth_method_names := {"auth_method"}

hash_func_patterns := {"md5", "sha1", "sha-1", "des", "rc4"}
crypto_func_names := {"md5", "sha1", "sha-1", "des", "rc4", "crypt", "encrypt", "hash"}

is_weak_algorithm(str) {
    upper_str := upper(str)
    alg := weak_algorithms[_]
    contains(upper_str, alg)
}

is_weak_tls(str) {
    upper_str := upper(str)
    ver := weak_tls_versions[_]
    contains(upper_str, ver)
}

is_weak_ssl_policy(str) {
    upper_str := upper(str)
    pol := weak_ssl_policies[_]
    contains(upper_str, pol)
}

is_encryption_attr_name(name) {
    lower_name := lower(name)
    enc := encryption_attr_names[_]
    contains(lower_name, enc)
}

is_storage_encryption_attr(name) {
    lower_name := lower(name)
    enc := storage_encryption_names[_]
    contains(lower_name, enc)
}

is_auth_method_attr(name) {
    lower_name := lower(name)
    lower_name == "auth_method"
}

is_weak_cipher_value(str) {
    upper_str := upper(str)
    contains(upper_str, "CBC")
    contains(upper_str, "SHA")
    not contains(upper_str, "SHA256")
    not contains(upper_str, "SHA384")
}

is_weak_cipher_value(str) {
    upper_str := upper(str)
    contains(upper_str, "NULL")
}

is_weak_cipher_value(str) {
    upper_str := upper(str)
    contains(upper_str, "EXPORT")
}

is_weak_cipher_value(str) {
    upper_str := upper(str)
    contains(upper_str, "DES")
}

is_weak_cipher_value(str) {
    upper_str := upper(str)
    contains(upper_str, "RC4")
}

is_weak_key_size_int(val) {
    val < 128
    val > 0
}

is_weak_key_size_str(str) {
    regex.match("^(64|56|40|1024|512|768)$", str)
}

is_weak_hash_function(name) {
    func_lower := lower(name)
    pat := hash_func_patterns[_]
    contains(func_lower, pat)
}

is_known_crypto_function(name) {
    func_lower := lower(name)
    pat := crypto_func_names[_]
    contains(func_lower, pat)
}

is_crypto_function_call_like(name) {
    func_lower := lower(name)
    contains(func_lower, "md5") 
    not contains(func_lower, "acls_to_resources_hash")
    not contains(func_lower, "hiera_hash")
    not contains(func_lower, "md5hash")
    not contains(func_lower, "md5sum")
}

is_crypto_function_call_like(name) {
    func_lower := lower(name)
    contains(func_lower, "sha1")
}

is_crypto_function_call_like(name) {
    func_lower := lower(name)
    contains(func_lower, "des") 
}

is_crypto_function_call_like(name) {
    func_lower := lower(name)
    contains(func_lower, "rc4")
}

is_crypto_function_call_like(name) {
    func_lower := lower(name)
    contains(func_lower, "crypt")
    not contains(func_lower, "acls_to_resources_hash")
}

has_weak_arg(args) {
    arg := args[_]
    arg.ir_type == "String"
    is_weak_algorithm(arg.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_encryption_attr_name(node.name)
    node.value.ir_type == "String"
    is_weak_algorithm(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak or deprecated encryption algorithm detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_encryption_attr_name(node.name)
    node.value.ir_type == "String"
    is_weak_cipher_value(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher configuration detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    is_encryption_attr_name(node.name)
    node.value.ir_type == "String"
    is_weak_cipher_value(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher suite detected in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    is_weak_hash_function(node.name)
    has_weak_arg(node.args)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak algorithm passed to cryptographic function. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    is_crypto_function_call_like(node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak cryptographic hash function detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "FunctionCall"
    func := node.value
    is_weak_hash_function(func.name)
    has_weak_arg(func.args)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak algorithm in function call within attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "FunctionCall"
    func := node.value
    is_crypto_function_call_like(func.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak cryptographic hash function in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_encryption_attr_name(node.name)
    node.value.ir_type == "Integer"
    is_weak_key_size_int(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Encryption key size or iteration count below recommended minimum. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_encryption_attr_name(node.name)
    node.value.ir_type == "String"
    is_weak_key_size_str(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Encryption key size below recommended minimum. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    is_encryption_attr_name(node.name)
    node.value.ir_type == "Integer"
    is_weak_key_size_int(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Encryption key size below recommended minimum in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_encryption_attr_name(node.name)
    node.value.ir_type == "String"
    is_weak_tls(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak TLS/SSL version detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_encryption_attr_name(node.name)
    node.value.ir_type == "String"
    is_weak_ssl_policy(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak SSL/TLS policy detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    contains(lower(node.name), "cipher")
    node.value.ir_type == "String"
    is_weak_cipher_value(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher suite detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    contains(lower(node.name), "cipher")
    node.value.ir_type == "String"
    is_weak_cipher_value(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher suite detected in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_storage_encryption_attr(node.name)
    node.value.ir_type == "Boolean"
    node.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Encryption disabled or set to false. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_auth_method_attr(node.name)
    node.value.ir_type == "String"
    is_weak_algorithm(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak authentication/cryptographic method detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    some key_val, val_val
    kv[key_val] = val_val
    key_val.ir_type == "String"
    is_encryption_attr_name(key_val.value)
    val_val.ir_type == "String"
    is_weak_algorithm(val_val.value)
    result := {
        "type": "sec_weak_crypt",
        "element": val_val,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak encryption algorithm in nested configuration. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    some key_val, val_val
    kv[key_val] = val_val
    key_val.ir_type == "String"
    is_encryption_attr_name(key_val.value)
    val_val.ir_type == "String"
    is_weak_cipher_value(val_val.value)
    result := {
        "type": "sec_weak_crypt",
        "element": val_val,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher suite in nested configuration. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    kv := node.value[_]
    some key_val, val_val
    kv[key_val] = val_val
    val_val.ir_type == "String"
    is_weak_algorithm(val_val.value)
    result := {
        "type": "sec_weak_crypt",
        "element": val_val,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Array"
    arr := node.value[_]
    arr.ir_type == "Hash"
    kv := arr.value[_]
    some key_val, val_val
    kv[key_val] = val_val
    key_val.ir_type == "String"
    is_encryption_attr_name(key_val.value)
    val_val.ir_type == "String"
    is_weak_algorithm(val_val.value)
    result := {
        "type": "sec_weak_crypt",
        "element": val_val,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak encryption algorithm in array configuration. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Array"
    arr := node.value[_]
    arr.ir_type == "Hash"
    kv := arr.value[_]
    some key_val, val_val
    kv[key_val] = val_val
    key_val.ir_type == "String"
    lower(key_val.value) == "auth_method"
    val_val.ir_type == "String"
    is_weak_algorithm(val_val.value)
    result := {
        "type": "sec_weak_crypt",
        "element": val_val,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak authentication method in array configuration. (CWE-326)"
    }
}