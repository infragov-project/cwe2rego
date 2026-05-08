package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC4", "AES-128", "Blowfish", "SHA-1", "RSA-1024", "DSA-1024", "MD5", "md5_crypt"}
insufficient_key_lengths := {1024, 128, 512}
outdated_protocols := {"TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2", "TLS_1_0", "TLS_1_1"}
weak_cipher_suites := {"CBC", "DES", "RC4", "EXPORT", "NULL", "DES-CBC3-SHA", "RC4-SHA"}
static_key_indicators := {"false", "disabled", "0"}

algorithm_keywords := {"algorithm", "cipher", "encryption_type", "encrypt"}
key_length_keywords := {"key_size", "bit_length", "key_length", "modulus_length"}
protocol_keywords := {"protocol", "ssl_policy", "tls_version", "min_protocol_version"}
cipher_suite_keywords := {"ciphers", "cipher_suites", "ssl_ciphers"}
rotation_keywords := {"rotation", "key_lifetime", "static_key"}

contains_weak_algorithm(str) {
    alg := weak_algorithms[_]
    regex.match(sprintf("(?i).*%s.*", [lower(alg)]), lower(str))
}

contains_insufficient_key_length(value) {
    value.ir_type == "Integer"
    insufficient_key_lengths[value.value]
} else {
    value.ir_type == "String"
    length_str := to_string(insufficient_key_lengths[_])
    value.value == length_str
}

contains_outdated_protocol(str) {
    protocol := outdated_protocols[_]
    regex.match(sprintf("(?i).*%s.*", [lower(protocol)]), lower(str))
}

contains_weak_cipher_suite(str) {
    cipher := weak_cipher_suites[_]
    regex.match(sprintf("(?i).*%s.*", [lower(cipher)]), lower(str))
}

contains_static_key(value) {
    value.ir_type == "String"
    lower_value := lower(value.value)
    indicator := static_key_indicators[_]
    regex.match(sprintf("(?i).*%s.*", [lower(indicator)]), lower_value)
} else {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "Integer"
    value.value == 0
}

contains_weak_function(call) {
    call.ir_type == "FunctionCall"
    contains_weak_algorithm(call.name)
} else {
    call.ir_type == "FunctionCall"
    arg := call.args[_]
    arg.ir_type == "String"
    contains_weak_algorithm(arg.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    algorithm_keywords[attr.name]
    attr.value.ir_type == "String"
    contains_weak_algorithm(attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected - Using inadequate cryptographic algorithms may lead to data exposure. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    key_length_keywords[attr.name]
    contains_insufficient_key_length(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Insufficient key length detected - Short cryptographic keys are vulnerable to brute-force attacks. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    protocol_keywords[attr.name]
    attr.value.ir_type == "String"
    contains_outdated_protocol(attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Outdated protocol detected - Deprecated protocols lack modern security mitigations. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    cipher_suite_keywords[attr.name]
    attr.value.ir_type == "String"
    contains_weak_cipher_suite(attr.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cipher suite detected - Insecure cipher suites may expose encrypted data. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    rotation_keywords[attr.name]
    contains_static_key(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Static or unrotated key detected - Fixed keys increase the impact of compromise. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attr := attributes[_]
    attr.value.ir_type == "FunctionCall"
    contains_weak_function(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption algorithm detected - Using inadequate cryptographic algorithms may lead to data exposure. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "String"
    contains_weak_algorithm(var.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Weak encryption algorithm detected - Using inadequate cryptographic algorithms may lead to data exposure. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "FunctionCall"
    contains_weak_function(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Weak encryption algorithm detected - Using inadequate cryptographic algorithms may lead to data exposure. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    contains_insufficient_key_length(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Insufficient key length detected - Short cryptographic keys are vulnerable to brute-force attacks. (CWE-326)"
    }
}