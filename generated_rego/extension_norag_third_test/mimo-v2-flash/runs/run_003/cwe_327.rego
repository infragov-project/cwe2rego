package glitch

import data.glitch_lib

weak_crypto_patterns := {"des", "3des", "tripledes", "rc4", "md5", "sha1", "blowfish", "dsa", "aes-128", "aes128", "rsa-1024", "rsa1024", "dsa-1024", "dsa1024", "ssl", "sslv2", "sslv3", "tls1.0", "tls1.1", "tls1_0", "tls1_1", "tls-1-0", "tls-1-1", "tlsv1.0", "tlsv1.1", "md5_crypt", "sha1withrsa", "sha1withdsa", "md5withrsa", "cbc", "elbsecuritypolicy-tls-1-0"}

crypto_attributes := {"algorithm", "encryption_algorithm", "cipher", "ssl_policy", "tls_version", "signature_algorithm", "hash_algorithm", "protocols", "min_tls_version", "ssl_protocol", "ciphers", "allowed_ciphers", "security_policy", "key_algorithm", "public_key_algorithm", "hashing_algorithm", "password_hash_algorithm", "mac_algorithm", "key_size", "rsa_key_size", "bit_length", "kdf_iterations", "pbkdf2_iterations", "bcrypt_cost", "cost_factor", "encrypt", "encryption", "password", "private_key"}

is_crypto_attribute(name) {
    lower_name := lower(name)
    attr := crypto_attributes[_]
    lower_name == lower(attr)
} else {
    lower_name := lower(name)
    regex.match(".*(ssl|tls|cipher|encrypt|algorithm|hash|key|crypt|signature|mac|kdf|pbkdf|bcrypt|password).*", lower_name)
}

is_weak_string_value(val) {
    val.ir_type == "String"
    lower_val := lower(val.value)
    pattern := weak_crypto_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), lower_val)
}

is_weak_int_value(val) {
    val.ir_type == "Integer"
    val.value > 0
    val.value <= 1024
}

has_weak_crypto_in_value(val) {
    walk(val, [path, node])
    is_weak_string_value(node)
}

has_weak_crypto_in_value(val) {
    walk(val, [path, node])
    is_weak_int_value(node)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_crypto_attribute(attr.name)
    has_weak_crypto_in_value(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Detected weak cryptographic algorithm, cipher, or key length in configuration. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]

    is_crypto_attribute(variable.name)
    has_weak_crypto_in_value(variable.value)

    result := {
        "type": "sec_weak_crypt",
        "element": variable,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Detected weak cryptographic algorithm, cipher, or key length in configuration. (CWE-327)"
    }
}