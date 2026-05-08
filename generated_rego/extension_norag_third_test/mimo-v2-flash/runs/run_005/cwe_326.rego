package glitch

import data.glitch_lib

crypto_attributes := {"algorithm", "cipher", "encryption_type", "kms_key_spec", "key_length", "key_size", "modulus_size", "rsa_key_bits", "key_spec", "protocol", "ssl_version", "tls_version", "min_tls_version", "security_policy", "initialization_vector", "nonce", "salt", "random_bytes", "enabled", "encryption_enabled", "storage_encrypted", "encrypt_at_rest", "secure_socket_layer", "secret_key", "api_key", "password", "token", "master_key", "encrypt", "cipher_suites"}

algorithm_attributes := {"algorithm", "cipher", "encryption_type", "kms_key_spec"}

protocol_attributes := {"protocol", "ssl_version", "tls_version", "min_tls_version", "security_policy"}

weak_algorithms := {"des", "3des", "tripledes", "rc4", "aes-128", "blowfish", "rc2", "sha1", "md5", "md5_crypt", "sunx509"}

weak_protocols := {"ssl v2.0", "ssl v3.0", "tls 1.0", "tls 1.1", "null-sha", "export"}

missing_encryption_values := {false, "disabled", "none"}

check_weak_algorithm(value) {
    value.ir_type == "String"
    lower_value := lower(value.value)
    count({algo | algo := weak_algorithms[_]; contains(lower_value, algo)}) > 0
} else {
    value.ir_type == "FunctionCall"
    count({arg | arg := value.args[_]; arg.ir_type == "String"; lower_arg := lower(arg.value); algo := weak_algorithms[_]; contains(lower_arg, algo)}) > 0
} else {
    value.ir_type == "Array"
    count({elem | elem := value.value[_]; elem.ir_type == "String"; lower_elem := lower(elem.value); algo := weak_algorithms[_]; contains(lower_elem, algo)}) > 0
}

check_weak_protocol(value) {
    value.ir_type == "String"
    lower_value := lower(value.value)
    count({proto | proto := weak_protocols[_]; contains(lower_value, proto)}) > 0
} else {
    value.ir_type == "Array"
    count({elem | elem := value.value[_]; elem.ir_type == "String"; lower_elem := lower(elem.value); proto := weak_protocols[_]; contains(lower_elem, proto)}) > 0
}

check_weak_key_length(attr_name, value) {
    value.ir_type == "Integer"
    {"key_length", "key_size", "modulus_size", "key_spec"}[attr_name]
    value.value < 128
} else {
    value.ir_type == "Integer"
    {"rsa_key_bits"}[attr_name]
    value.value < 2048
} else {
    value.ir_type == "String"
    regex.match("^[0-9]+$", value.value)
    {"key_length", "key_size", "modulus_size", "key_spec"}[attr_name]
    to_number(value.value) < 128
} else {
    value.ir_type == "String"
    regex.match("^[0-9]+$", value.value)
    {"rsa_key_bits"}[attr_name]
    to_number(value.value) < 2048
}

check_disabled_encryption(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    missing_encryption_values[value.value]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    algorithm_attributes[attr.name]
    check_weak_algorithm(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak cryptographic algorithm used. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    protocol_attributes[attr.name]
    check_weak_protocol(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak protocol version used. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    crypto_attributes[attr.name]
    check_weak_key_length(attr.name, attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Inadequate key length for encryption. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    {"enabled", "encryption_enabled", "storage_encrypted", "encrypt_at_rest", "secure_socket_layer"}[attr.name]
    check_disabled_encryption(attr.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Missing or disabled encryption. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    attr.name in {"secret_key", "api_key", "password", "token", "master_key"}
    value := attr.value
    value.ir_type == "String"
    value.value != ""
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded encryption secret. (CWE-326)"
    }
}