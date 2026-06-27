package glitch

import data.glitch_lib

weak_algorithms := {"des", "3des", "rc4", "rc2", "blowfish", "md5", "sha1", "sha-1", "md-5", "md4", "ripemd", "ripemd160", "md5_crypt", "sha", "sunx509", "md2", "ripemd128", "whirlpool", "tiger", "snefru", "gost", "aria-128-cbc", "aria-192-cbc", "seed-cbc", "rc5", "cast5", "idea", "desx", "des-ede", "des-ede3", "rc4-hmac", "arcfour", "arcfour128", "arcfour256"}

protocol_weak_indicators := {"sslv2", "sslv3", "sslv2.3", "tlsv1.0", "tlsv1.1", "tls1.0", "tls1.1", "tlsv1", "tlsv1_0", "tlsv1_1", "sslv2.0", "sslv3.0", "ssl_2", "ssl_3"}

crypto_attr_exact := {"encrypt", "encryption", "cipher", "cipher_suite", "cipher_suites", "algorithm", "signature_algorithm", "signing_algorithm", "encryption_algorithm", "key_algorithm", "key_spec", "kms_key_spec", "protocol", "tls_version", "minimum_protocol_version", "security_policy", "ssl_policy", "allowed_ciphers", "hash", "digest", "mac", "hmac", "pbkdf", "kdf", "checksum", "crypt", "kex", "cipher_suites", "ssl_protocol", "tls_protocol"}

password_context_attrs := {"password", "password_md5", "password_sha1", "secret", "credential", "credentials", "private_key", "sensitive"}

weak_cipher_indicators := {"_cbc", "_ecb", "null_", "anon_", "export_", "_des_", "_3des_", "_rc4_", "_md5", "_sha1", "rc4", "des", "3des", "md5", "sha1"}

weak_key_size_attrs := {"key_size", "key_length", "bits", "modulus_size", "rsa_key_size", "salt_size", "salt_length", "iterations", "rounds"}

contains_weak_algorithm(val) {
    algo := weak_algorithms[_]
    regex.match(sprintf("(?i)(?:^|[^a-z0-9_-])%s(?:[^a-z0-9_-]|$)", [algo]), val)
}

contains_weak_protocol(val) {
    proto := protocol_weak_indicators[_]
    regex.match(sprintf("(?i)(?:^|[^a-z0-9._-])%s(?:[^a-z0-9._-]|$)", [proto]), val)
}

has_weak_cipher_value(val) {
    indicator := weak_cipher_indicators[_]
    regex.match(sprintf("(?i)%s", [indicator]), val)
}

is_exact_crypto_attr(name) {
    attr := crypto_attr_exact[_]
    regex.match(sprintf("(?i)^%s$", [attr]), name)
}

is_key_size_attr(name) {
    attr := weak_key_size_attrs[_]
    regex.match(sprintf("(?i)%s", [attr]), name)
}

is_password_context_attr(name) {
    attr := password_context_attrs[_]
    regex.match(sprintf("(?i)%s", [attr]), name)
}

get_string_values(node) = vals {
    vals = {v |
        walk(node, [_, n])
        n.ir_type == "String"
        v := lower(n.value)
    }
}

get_all_values_recursive(node) = vals {
    vals = {v |
        walk(node, [_, n])
        n.ir_type == "String"
        v := lower(n.value)
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Hash"
    
    entries := {e | e := node.value[_]}
    entry := entries[_]
    
    entry.key.ir_type == "String"
    key_name := lower(entry.key.value)
    
    is_exact_crypto_attr(key_name)
    
    strvals := get_string_values(entry.value)
    val := strvals[_]
    
    contains_weak_algorithm(val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": entry,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in hash entry detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    
    attr_name := lower(node.name)
    
    is_exact_crypto_attr(attr_name)
    
    strvals := get_string_values(node.value)
    val := strvals[_]
    
    contains_weak_algorithm(val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in attribute detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Variable"
    
    var_name := lower(node.name)
    
    is_exact_crypto_attr(var_name)
    
    strvals := get_string_values(node.value)
    val := strvals[_]
    
    contains_weak_algorithm(val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in variable detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Variable"
    
    var_name := lower(node.name)
    
    is_password_context_attr(var_name)
    
    strvals := get_string_values(node.value)
    val := strvals[_]
    
    contains_weak_algorithm(val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak algorithm used for password/credential. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    
    attr_name := lower(node.name)
    
    is_exact_crypto_attr(attr_name)
    
    strvals := get_string_values(node.value)
    val := strvals[_]
    
    contains_weak_protocol(val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Deprecated TLS/SSL protocol version detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    
    attr_name := lower(node.name)
    
    regex.match("(?i)cipher_suite|cipher_suites|allowed_ciphers", attr_name)
    
    strvals := get_string_values(node.value)
    val := strvals[_]
    
    has_weak_cipher_value(val)
    
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
    
    node.ir_type == "Hash"
    
    entries := {e | e := node.value[_]}
    entry := entries[_]
    
    entry.key.ir_type == "String"
    key_name := lower(entry.key.value)
    
    regex.match("(?i)cipher_suite|cipher_suites|allowed_ciphers", key_name)
    
    strvals := get_string_values(entry.value)
    val := strvals[_]
    
    has_weak_cipher_value(val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": entry,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher suite in hash detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "FunctionCall"
    
    func_name := lower(node.name)
    
    regex.match("(?i)hash|encrypt|digest|cipher|md5|sha1", func_name)
    
    args_strvals := get_string_values({"value": node.args})
    val := args_strvals[_]
    
    contains_weak_algorithm(val)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak algorithm in cryptographic function call detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    
    attr_name := lower(node.name)
    
    is_key_size_attr(attr_name)
    
    node.value.ir_type == "Integer"
    node.value.value < 128
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Insufficient key size detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    
    attr_name := lower(node.name)
    
    regex.match("(?i)password.*md5|password.*sha1|md5.*password|sha1.*password", attr_name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak hash algorithm indicated for password. (CWE-326)"
    }
}