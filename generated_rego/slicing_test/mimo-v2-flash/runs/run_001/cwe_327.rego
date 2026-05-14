package glitch

import data.glitch_lib

weak_encryption_algorithms := {"DES", "3DES", "RC4", "BLOWFISH", "TEA", "XTEA", "ARCFOUR"}
weak_hashing_algorithms := {"MD5", "SHA1", "SHA-1", "md5_crypt", "sha1", "md5"}
weak_encryption_modes := {"ECB"}
weak_protocols := {"SSLv3", "TLS_1.0", "TLS_1.1"}
weak_key_algorithms := {"RSA-1024"}
pseudo_crypto := {"Base64", "XOR", "ROT13"}
weak_cipher_suites := {"TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA"}

cryptographic_attributes := {"algorithm", "encryption_type", "server_side_encryption", "cipher_suite", "hashing_algorithm", "hash_function", "signature_algorithm", "password_hashing_algorithm", "certificate_signature_algorithm", "mode", "block_cipher_mode", "protocol", "ssl_policy", "tls_version", "key_algorithm", "encoding", "obfuscation_method", "encrypt"}

cryptographic_keywords := {"password", "hash", "cipher", "encrypt", "algorithm", "mode", "protocol", "key", "encoding", "obfuscation"}

contains_crypto_keyword(name) {
    name_lower := lower(name)
    keyword := cryptographic_keywords[_]
    glitch_lib.contains(name_lower, lower(keyword))
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cryptographic_attributes[_]
    attr.value.ir_type == "String"
    value_lower := lower(attr.value.value)
    weak_algo := weak_encryption_algorithms[_]
    glitch_lib.contains(value_lower, lower(weak_algo))
    result := {"type": "sec_weak_crypt", "element": attr, "path": parent.path, "description": "Use of weak encryption algorithm - Avoid using broken or risky cryptographic algorithms. (CWE-327)"}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cryptographic_attributes[_]
    attr.value.ir_type == "String"
    value_lower := lower(attr.value.value)
    weak_hash := weak_hashing_algorithms[_]
    glitch_lib.contains(value_lower, lower(weak_hash))
    result := {"type": "sec_weak_crypt", "element": attr, "path": parent.path, "description": "Use of weak hashing algorithm - Avoid using broken or risky cryptographic algorithms. (CWE-327)"}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cryptographic_attributes[_]
    attr.value.ir_type == "String"
    value_lower := lower(attr.value.value)
    weak_mode := weak_encryption_modes[_]
    glitch_lib.contains(value_lower, lower(weak_mode))
    result := {"type": "sec_weak_crypt", "element": attr, "path": parent.path, "description": "Use of weak encryption mode - Avoid using broken or risky cryptographic modes. (CWE-327)"}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cryptographic_attributes[_]
    attr.value.ir_type == "String"
    value_lower := lower(attr.value.value)
    weak_protocol := weak_protocols[_]
    glitch_lib.contains(value_lower, lower(weak_protocol))
    result := {"type": "sec_weak_crypt", "element": attr, "path": parent.path, "description": "Use of weak protocol - Avoid using deprecated protocols with known vulnerabilities. (CWE-327)"}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cryptographic_attributes[_]
    attr.value.ir_type == "String"
    value_lower := lower(attr.value.value)
    weak_key := weak_key_algorithms[_]
    glitch_lib.contains(value_lower, lower(weak_key))
    result := {"type": "sec_weak_crypt", "element": attr, "path": parent.path, "description": "Use of weak key algorithm - Avoid using short keys or weak signatures. (CWE-327)"}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cryptographic_attributes[_]
    attr.value.ir_type == "String"
    value_lower := lower(attr.value.value)
    pseudo := pseudo_crypto[_]
    glitch_lib.contains(value_lower, lower(pseudo))
    result := {"type": "sec_weak_crypt", "element": attr, "path": parent.path, "description": "Use of pseudo-cryptography - Avoid using encoding instead of encryption to protect secrets. (CWE-327)"}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cryptographic_attributes[_]
    attr.value.ir_type == "String"
    value_lower := lower(attr.value.value)
    weak_suite := weak_cipher_suites[_]
    glitch_lib.contains(value_lower, lower(weak_suite))
    result := {"type": "sec_weak_crypt", "element": attr, "path": parent.path, "description": "Use of weak cipher suite - Avoid using cipher suites with weak algorithms. (CWE-327)"}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    contains_crypto_keyword(var.name)
    var.value.ir_type == "String"
    value_lower := lower(var.value.value)
    weak_algo := weak_encryption_algorithms[_]
    glitch_lib.contains(value_lower, lower(weak_algo))
    result := {"type": "sec_weak_crypt", "element": var, "path": parent.path, "description": "Use of weak encryption algorithm - Avoid using broken or risky cryptographic algorithms. (CWE-327)"}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    contains_crypto_keyword(var.name)
    var.value.ir_type == "String"
    value_lower := lower(var.value.value)
    weak_hash := weak_hashing_algorithms[_]
    glitch_lib.contains(value_lower, lower(weak_hash))
    result := {"type": "sec_weak_crypt", "element": var, "path": parent.path, "description": "Use of weak hashing algorithm - Avoid using broken or risky cryptographic algorithms. (CWE-327)"}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    func_name_lower := lower(node.name)
    weak_func := {"md5", "sha1", "sha-1"}
    glitch_lib.contains(func_name_lower, weak_func[_])
    result := {"type": "sec_weak_crypt", "element": node, "path": parent.path, "description": "Use of weak hashing algorithm - Avoid using broken or risky cryptographic algorithms. (CWE-327)"}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    node.name == "filter|hash"
    count(node.args) > 1
    arg := node.args[1]
    arg.ir_type == "String"
    arg_value_lower := lower(arg.value)
    weak_hash := weak_hashing_algorithms[_]
    glitch_lib.contains(arg_value_lower, lower(weak_hash))
    result := {"type": "sec_weak_crypt", "element": node, "path": parent.path, "description": "Use of weak hashing algorithm - Avoid using broken or risky cryptographic algorithms. (CWE-327)"}
}