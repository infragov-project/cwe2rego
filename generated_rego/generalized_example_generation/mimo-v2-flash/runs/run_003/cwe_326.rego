package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "TripleDES", "RC4", "ARC4", "ARCFOUR", "Blowfish", "RC2", "MD5", "SHA1", "SHA-1", "HMAC-MD5", "HMAC-SHA1", "PBKDF1", "RSA-1024"}
insecure_modes := {"ECB"}
deprecated_protocols := {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "1.0", "1.1", "TLS1.0", "TLS1.1"}
weak_signature_algorithms := {"SHA1", "MD5"}
weak_kdfs := {"PBKDF1", "BCRYPT", "SCRYPT"}
weak_key_lengths := {512, 768, 1024}

algorithm_keywords := {"algorithm", "encryption", "cipher", "signature", "digest", "sse", "ssl", "tls", "protocol", "kdf", "pbkdf", "bcrypt", "scrypt", "min_tls", "ssl_protocol", "ssl_cipher"}
key_length_keywords := {"key_length", "key_size", "key_spec", "min_key", "bits", "rsa", "dsa", "ecdsa", "key"}
mode_keywords := {"mode", "cipher_mode"}
iteration_keywords := {"iterations", "cost", "work", "rounds"}

weak_algorithm_found(value) {
    value.ir_type == "String"
    lower_value := lower(value.value)
    weak := weak_algorithms[_]
    contains(lower_value, lower(weak))
}

weak_algorithm_found(value) {
    value.ir_type == "Array"
    item := value.value[_]
    item.ir_type == "String"
    lower_value := lower(item.value)
    weak := weak_algorithms[_]
    contains(lower_value, lower(weak))
}

deprecated_protocol_found(value) {
    value.ir_type == "String"
    lower_value := lower(value.value)
    protocol := deprecated_protocols[_]
    contains(lower_value, lower(protocol))
}

deprecated_protocol_found(value) {
    value.ir_type == "Array"
    item := value.value[_]
    item.ir_type == "String"
    lower_value := lower(item.value)
    protocol := deprecated_protocols[_]
    contains(lower_value, lower(protocol))
}

insecure_mode_found(value) {
    value.ir_type == "String"
    lower_value := lower(value.value)
    mode := insecure_modes[_]
    contains(lower_value, lower(mode))
}

key_length_too_low(value) {
    value.ir_type == "Integer"
    value.value < 128
}

key_length_too_low(value) {
    value.ir_type == "Integer"
    weak_key_lengths[value.value]
}

iterations_too_low(value) {
    value.ir_type == "Integer"
    value.value < 100000
}

cost_too_low(value) {
    value.ir_type == "Integer"
    value.value < 10
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    name := attr.name
    value := attr.value
    lower_name := lower(name)
    keyword := algorithm_keywords[_]
    contains(lower_name, keyword)
    weak_algorithm_found(value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm detected."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    name := attr.name
    value := attr.value
    lower_name := lower(name)
    keyword := algorithm_keywords[_]
    contains(lower_name, keyword)
    deprecated_protocol_found(value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Deprecated protocol detected."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    name := var.name
    value := var.value
    lower_name := lower(name)
    keyword := algorithm_keywords[_]
    contains(lower_name, keyword)
    weak_algorithm_found(value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm detected."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    name := var.name
    value := var.value
    lower_name := lower(name)
    keyword := algorithm_keywords[_]
    contains(lower_name, keyword)
    deprecated_protocol_found(value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Deprecated protocol detected."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    name := attr.name
    value := attr.value
    lower_name := lower(name)
    keyword := key_length_keywords[_]
    contains(lower_name, keyword)
    key_length_too_low(value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Insufficient key length detected."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    name := var.name
    value := var.value
    lower_name := lower(name)
    keyword := key_length_keywords[_]
    contains(lower_name, keyword)
    key_length_too_low(value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Insufficient key length detected."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    name := attr.name
    value := attr.value
    lower_name := lower(name)
    keyword := mode_keywords[_]
    contains(lower_name, keyword)
    insecure_mode_found(value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Insecure mode of operation (ECB) detected."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    name := var.name
    value := var.value
    lower_name := lower(name)
    keyword := mode_keywords[_]
    contains(lower_name, keyword)
    insecure_mode_found(value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Insecure mode of operation (ECB) detected."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    name := attr.name
    value := attr.value
    lower_name := lower(name)
    keyword := iteration_keywords[_]
    contains(lower_name, keyword)
    iterations_too_low(value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Low iteration count in key derivation."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    name := attr.name
    value := attr.value
    lower_name := lower(name)
    keyword := iteration_keywords[_]
    contains(lower_name, keyword)
    cost_too_low(value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Low cost factor in key derivation."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    name := var.name
    value := var.value
    lower_name := lower(name)
    keyword := iteration_keywords[_]
    contains(lower_name, keyword)
    iterations_too_low(value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Low iteration count in key derivation."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    name := var.name
    value := var.value
    lower_name := lower(name)
    keyword := iteration_keywords[_]
    contains(lower_name, keyword)
    cost_too_low(value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Low cost factor in key derivation."
    }
}