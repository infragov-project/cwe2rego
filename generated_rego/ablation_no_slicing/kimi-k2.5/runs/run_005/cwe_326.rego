package glitch

import data.glitch_lib
import future.keywords.in

weak_algorithms := {"DES", "3DES", "RC2", "RC4", "Blowfish", "ECB", "MD5", "SHA1", "SHA-1", "MD-5", "md5", "sha1", "md5_crypt", "sha1_crypt", "des", "3des", "rc2", "rc4", "blowfish", "ecb"}
weak_tls_versions_1 := {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLS1.0", "TLS1.1", "1.0", "1.1", "sslv2", "sslv3", "tlsv1.0", "tlsv1.1", "tls1.0", "tls1.1"}
weak_cipher_patterns := {"RSA_WITH", "CBC", "DES", "3DES", "RC4", "NULL", "EXPORT", "anon", "eNULL", "aNULL"}
weak_hash_functions := {"md5", "sha1", "MD5", "SHA1"}
min_rsa_size := 2048
min_symmetric_size := 128

encryption_attr_patterns := "^(?i)(encrypt|cipher|crypto|hash|digest|auth_method|algorithm|tls|ssl|kdf|pbkdf|bcrypt|scrypt|argon2|mode)$"
key_size_patterns := "^(?i).*(key.*size|key.*length|modulus|bits|rsa.*size).*$"
tls_version_patterns := "^(?i).*(tls|ssl|version|protocol).*$"
cipher_suite_patterns := "^(?i).*(cipher.*suite|enabled.*cipher|cipher_suites).*$"
explicit_weak_patterns := "^(?i).*(allow_weak|use_insecure|disable_security|enable_weak|legacy|allow_legacy|compatibility).*$"

is_weak_algorithm(value) {
    lower(value) == weak_algorithms[_]
}

is_weak_algorithm(value) {
    regex.match("(?i)\\b(DES|3DES|RC2|RC4|Blowfish|ECB|MD5|SHA1|SHA-1|MD-5|md5_crypt|sha1_crypt)\\b", value)
}

is_weak_tls_version(value) {
    lower(value) == weak_tls_versions_1[_]
}

is_weak_cipher_suite(value) {
    some pattern in weak_cipher_patterns
    regex.match(sprintf(".*%s.*", [pattern]), value)
}

is_weak_key_size(attr_name, value) {
    regex.match(key_size_patterns, attr_name)
    value.ir_type == "Integer"
    value.value < min_symmetric_size
    value.value > 0
}

is_weak_rsa_size(attr_name, value) {
    regex.match("(?i)rsa|modulus", attr_name)
    value.ir_type == "Integer"
    value.value < min_rsa_size
    value.value >= 512
}

is_encryption_attribute(name) {
    regex.match(encryption_attr_patterns, name)
}

is_explicit_weak_enable(attr_name, value) {
    regex.match(explicit_weak_patterns, attr_name)
    value.ir_type == "Boolean"
    value.value == true
}

is_encryption_disabled(attr_name, value) {
    regex.match("(?i)^encrypted?$", attr_name)
    value.ir_type == "Boolean"
    value.value == false
}

check_string_value_for_weak_crypto(str) {
    is_weak_algorithm(str)
}

check_string_value_for_weak_crypto(str) {
    is_weak_tls_version(str)
}

check_string_value_for_weak_crypto(str) {
    is_weak_cipher_suite(str)
}

check_value_for_weak_crypto(value) {
    walk(value, [_, n])
    n.ir_type == "String"
    check_string_value_for_weak_crypto(n.value)
}

check_function_call_weak_crypto(node) {
    node.ir_type == "FunctionCall"
    lower(node.name) == weak_hash_functions[_]
}

check_function_call_weak_crypto(node) {
    node.ir_type == "FunctionCall"
    regex.match("(?i)^filter\\|hash$", node.name)
    arg := node.args[_]
    arg.ir_type == "String"
    is_weak_algorithm(arg.value)
}

check_access_for_weak_crypto(node) {
    node.ir_type == "Access"
    node.right.ir_type == "String"
    regex.match("(?i)password.*md5|password.*sha1|md5.*hash|sha1.*hash", node.right.value)
}

check_variable_name_for_cipher_suites(name) {
    regex.match(cipher_suite_patterns, name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_encryption_attribute(node.name)
    check_value_for_weak_crypto(node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm or configuration detected in attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_encryption_attribute(node.name)
    node.value.ir_type == "String"
    is_weak_algorithm(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in attribute value. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_weak_key_size(node.name, node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak key size detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_weak_rsa_size(node.name, node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak RSA key size detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    regex.match(tls_version_patterns, node.name)
    node.value.ir_type == "String"
    is_weak_tls_version(node.value.value)
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
    regex.match(cipher_suite_patterns, node.name)
    node.value.ir_type == "String"
    is_weak_cipher_suite(node.value.value)
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
    node.ir_type == "Attribute"
    is_explicit_weak_enable(node.name, node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Explicit weak cryptography enabled. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_encryption_disabled(node.name, node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Encryption explicitly disabled. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    is_encryption_attribute(node.name)
    check_value_for_weak_crypto(node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    is_weak_key_size(node.name, node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak key size in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    is_weak_rsa_size(node.name, node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak key size in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    check_function_call_weak_crypto(node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Use of weak cryptographic function. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.name == "password"
    check_access_for_weak_crypto(node.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Password attribute using weak hash algorithm. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    is_encryption_attribute(entry.key.value)
    entry.value.ir_type == "String"
    is_weak_algorithm(entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in hash entry. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Array"
    elem := node.value[_]
    elem.ir_type == "Hash"
    entry := elem.value[_]
    entry.key.ir_type == "String"
    is_encryption_attribute(entry.key.value)
    entry.value.ir_type == "String"
    is_weak_algorithm(entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry.value,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in array of hashes. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    check_variable_name_for_cipher_suites(node.name)
    node.value.ir_type == "String"
    is_weak_cipher_suite(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher suite in variable. (CWE-326)"
    }
}