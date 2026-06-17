package glitch

import data.glitch_lib
import future.keywords.in

weak_algorithm_attrs = {"encryption_algorithm", "cipher", "algorithm", "crypto_provider", "hashing_algorithm", "key_wrap_algorithm", "encrypt", "password", "restore_service_username"}
weak_algorithms = {"DES", "3DES", "RC4", "AES-128", "RSA-1024", "MD5", "SHA-1", "sha1", "md5_crypt", "password_md5"}

key_length_attrs = {"key_length", "key_size", "bit_length", "encryption_bits", "rsa_key_bits"}
min_rsa_key = 2048
min_ecc_key = 224
min_symmetric_key = 128

protocol_attrs = {"protocol_version", "tls_version", "ssl_version", "min_protocol_version", "enabled_protocols", "cipher_suites"}
deprecated_protocols = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

encryption_enabled_attrs = {"encryption_enabled", "enable_encryption", "server_side_encryption", "encryption_at_rest", "encrypted_storage"}

key_management_attrs = {"key_management", "key_rotation", "key_source", "customer_managed_key", "auto_key_rotation"}

randomness_attrs = {"salt", "initialization_vector", "iv", "nonce", "randomness_source"}

cipher_suite_attrs = {"cipher_preference", "security_policy", "allowed_ciphers", "cipher_suites"}
weak_ciphers = {"DES", "RC4", "3DES", "MD5", "SHA1", "CAMELLIA", "ARIA", "AES_128", "AES-128"}

extract_pairs(node) = pairs {
    pairs1 := {{"name": n.name, "value": n.value} | walk(node, [_, n]); n.ir_type == "Attribute"}
    pairs2 := {{"name": n.name, "value": n.value} | walk(node, [_, n]); n.ir_type == "Variable"}
    pairs3 := {{"name": key_str, "value": value_node} | walk(node, [_, n]); n.ir_type == "Hash"; kv := n.value[_]; key_str := kv.key.value; value_node := kv.value}
    pairs4 := {{"name": key_str, "value": value_node} | walk(node, [_, n]); n.ir_type == "Array"; elem := n.value[_]; elem.ir_type == "Hash"; kv := elem.value[_]; key_str := kv.key.value; value_node := kv.value}
    pairs5 := {{"name": v.name, "value": v.value} | walk(node, [_, n]); n.ir_type == "ConditionalStatement"; s := n.statements[_]; s.ir_type == "Variable"; v := s}
    pairs := pairs1 | pairs2 | pairs3 | pairs4 | pairs5
}

check_weak_algorithm(value) {
    value.ir_type == "String"
    algorithm := lower(value.value)
    algorithm == lower(weak_algorithms[_])
}

check_weak_algorithm(value) {
    value.ir_type == "FunctionCall"
    algorithm := lower(value.name)
    algorithm == lower(weak_algorithms[_])
}

check_weak_algorithm(value) {
    value.ir_type == "FunctionCall"
    some arg in value.args
    arg.ir_type == "String"
    algorithm := lower(arg.value)
    algorithm == lower(weak_algorithms[_])
}

check_weak_algorithm(value) {
    walk(value, [_, node])
    node.ir_type == "String"
    algorithm := lower(node.value)
    algorithm == lower(weak_algorithms[_])
}

check_weak_algorithm(value) {
    walk(value, [_, node])
    node.ir_type == "FunctionCall"
    algorithm := lower(node.name)
    algorithm == lower(weak_algorithms[_])
}

check_key_length(attr_name, value) {
    walk(value, [_, node])
    node.ir_type == "Integer"
    attr_name == "rsa_key_bits"
    node.value < min_rsa_key
}

check_key_length(attr_name, value) {
    walk(value, [_, node])
    node.ir_type == "Integer"
    attr_name != "rsa_key_bits"
    node.value < min_symmetric_key
}

check_protocol(value) {
    walk(value, [_, node])
    node.ir_type == "String"
    deprecated_protocols[node.value]
}

check_protocol(value) {
    walk(value, [_, node])
    node.ir_type == "String"
    some deprecated in deprecated_protocols
    contains(node.value, deprecated)
}

check_encryption_enabled(value) {
    walk(value, [_, node])
    node.ir_type == "Boolean"
    node.value == false
}

check_key_management(attr_name, value) {
    walk(value, [_, node])
    node.ir_type == "Boolean"
    attr_name == "key_rotation"
    node.value == false
}

check_key_management(attr_name, value) {
    walk(value, [_, node])
    node.ir_type == "String"
    attr_name == "key_rotation"
    lower(node.value) == "disabled"
}

check_key_management(attr_name, value) {
    walk(value, [_, node])
    node.ir_type == "Boolean"
    attr_name == "customer_managed_key"
    node.value == false
}

check_randomness(value) {
    walk(value, [_, node])
    node.ir_type == "String"
    node.value == ""
}

check_cipher_suite(value) {
    value.ir_type == "String"
    some cipher in weak_ciphers
    contains(value.value, cipher)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    pairs := extract_pairs(parent)
    pair := pairs[_]
    pair.name in weak_algorithm_attrs
    check_weak_algorithm(pair.value)
    element := pair

    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Weak cryptographic algorithm - Use of inadequate encryption strength (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    pairs := extract_pairs(parent)
    pair := pairs[_]
    some key in key_length_attrs
    pair.name == key
    check_key_length(key, pair.value)
    element := pair

    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Insufficient key length - Use of inadequate encryption strength (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    pairs := extract_pairs(parent)
    pair := pairs[_]
    some key in protocol_attrs
    pair.name == key
    check_protocol(pair.value)
    element := pair

    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Deprecated protocol - Use of inadequate encryption strength (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    pairs := extract_pairs(parent)
    pair := pairs[_]
    some key in encryption_enabled_attrs
    pair.name == key
    check_encryption_enabled(pair.value)
    element := pair

    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Lack of encryption for sensitive data - Use of inadequate encryption strength (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    pairs := extract_pairs(parent)
    pair := pairs[_]
    some key in key_management_attrs
    pair.name == key
    check_key_management(key, pair.value)
    element := pair

    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Insecure key management practices - Use of inadequate encryption strength (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    pairs := extract_pairs(parent)
    pair := pairs[_]
    some key in randomness_attrs
    pair.name == key
    check_randomness(pair.value)
    element := pair

    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Weak randomness or salting - Use of inadequate encryption strength (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    pairs := extract_pairs(parent)
    pair := pairs[_]
    some key in cipher_suite_attrs
    pair.name == key
    check_cipher_suite(pair.value)
    element := pair

    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Inadequate cipher suite configurations - Use of inadequate encryption strength (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    pairs := extract_pairs(parent)
    pair := pairs[_]
    contains(lower(pair.name), "cipher_suites")
    check_cipher_suite(pair.value)
    element := pair

    result := {
        "type": "sec_weak_crypt",
        "element": element,
        "path": parent.path,
        "description": "Inadequate cipher suite configurations - Use of inadequate encryption strength (CWE-326)"
    }
}