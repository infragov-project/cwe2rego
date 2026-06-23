package glitch

import data.glitch_lib

weak_algorithms = {"DES", "3DES", "RC4", "RC2", "BLOWFISH", "MD5", "SHA1", "SHA-1", "MD5_CRYPT", "MD5CRYPT"}

weak_tls_versions = {"SSLV2", "SSLV3", "TLSV1", "TLSV1.0", "TLSV1.1", "TLS1.0", "TLS1.1", "SSLV2.0", "SSLV3.0", "TLS10", "TLS11"}

weak_cipher_patterns = {"DES", "RC4", "NULL", "EXPORT", "ANON"}

weak_key_sizes = {512, 768, 1024}

weak_ssl_modes = {"disabled", "preferred", "optional", "false"}

encryption_key_keywords = {"algorithm", "encryption_type", "cipher", "crypto", "cryptographic", "symmetric", "asymmetric", "encrypt", "signature_algorithm", "key_algorithm", "digest", "hash", "checksum", "md5"}

key_size_keywords = {"key_size", "key_length", "bits", "modulus", "key_bits", "rsa_key_size", "key_length_bits", "salt_size"}

tls_version_keywords = {"tls_version", "ssl_version", "min_version", "protocol_version", "security_policy", "policy", "ike_version", "ipsec_policy", "vpn_type"}

cipher_suite_keywords = {"cipher_suite", "ciphers", "allowed_ciphers", "ssl_policy", "policy_name", "tls_policy", "cipher_suites", "phase1_integrity_algorithms", "phase2_encryption_algorithms"}

certificate_keywords = {"certificate", "cert", "private_key", "public_key", "key_algorithm", "signature_algorithm", "ssl_protocol", "ssl_certificate", "ssl_key"}

storage_encryption_keywords = {"sse_algorithm", "encryption", "encrypted", "kms_key_id", "server_side_encryption", "storage_encrypted", "require_ssl", "ssl_mode", "tls", "enable_advanced", "ssl"}

secret_keywords = {"type", "secure_string", "key_id", "data_type", "vars_prompt", "encrypt", "encryption_password", "encrypted_data"}

network_encryption_keywords = {"phase1_integrity_algorithms", "phase2_encryption_algorithms", "ike_version", "ipsec_policy", "vpn_type", "cipher_suites", "vpn_psk", "pfs_group"}

sensitive_data_keywords = {"password", "passwd", "secret", "key", "token", "credential", "auth", "private", "md5", "sha1", "encrypted"}

func_names_with_weak_args = {"hash", "digest", "md5", "sha1", "sha-1", "checksum", "md5_crypt", "md5crypt", "filter|hash", "filter|md5", "filter|sha1", "filter|sha-1", "filter|checksum"}

contains_str(str, substr) {
    contains(lower(str), lower(substr))
}

upper_str(s) = upper(s)

lower_str(s) = lower(s)

is_weak_algorithm_exact(s) {
    upper_str(s) == weak_algorithms[_]
}

is_weak_algorithm_substring(s) {
    contains_str(upper_str(s), weak_algorithms[_])
}

is_weak_tls_version(s) {
    norm := regex.replace(upper_str(regex.replace(regex.replace(regex.replace(s, ".", ""), "_", ""), "-", "")), "^V", "")
    weak_tls_versions[norm]
}

is_weak_cipher_pattern(s) {
    contains_str(upper_str(s), weak_cipher_patterns[_])
}

is_weak_key_size(n) {
    n < 2048
    n > 0
}

is_weak_ssl_mode(s) {
    lower_str(s) == weak_ssl_modes[_]
}

is_encryption_disabled(b) {
    b == false
}

name_matches_keyword(name, keywords) {
    kw := keywords[_]
    contains(lower_str(name), kw)
}

func_name_indicates_weak(name) {
    fname := func_names_with_weak_args[_]
    contains(lower_str(name), fname)
}

any_string_matches_weak(node, check_func) {
    node.ir_type == "String"
    check_func(node.value)
}

any_string_matches_weak(node, check_func) {
    node.ir_type == "VariableReference"
    check_func(node.value)
}

any_string_in_args_weak(args, check_func) {
    arg := args[_]
    any_string_matches_weak(arg, check_func)
}

any_string_in_args_weak(args, check_func) {
    arg := args[_]
    arg.ir_type == "Array"
    elem := arg.value[_]
    any_string_matches_weak(elem, check_func)
}

any_string_in_args_weak(args, check_func) {
    arg := args[_]
    arg.ir_type == "Hash"
    pair := arg.value[_]
    any_string_matches_weak(pair.key, check_func)
}

any_string_in_args_weak(args, check_func) {
    arg := args[_]
    arg.ir_type == "Hash"
    pair := arg.value[_]
    any_string_matches_weak(pair.value, check_func)
}

any_string_in_args_weak(args, check_func) {
    arg := args[_]
    arg.ir_type == "Access"
    any_string_matches_weak(arg.right, check_func)
}

build_result(element, parent_path, msg) = {
    "type": "sec_weak_crypt",
    "element": element,
    "path": parent_path,
    "description": sprintf("Inadequate Encryption Strength - %s (CWE-326)", [msg])
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    name_matches_keyword(node.name, encryption_key_keywords)
    
    node.value.ir_type == "String"
    is_weak_algorithm_exact(node.value.value)
    
    res := build_result(node.value, parent.path, "Use of weak encryption algorithm")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    name_matches_keyword(node.name, tls_version_keywords)
    
    node.value.ir_type == "String"
    is_weak_tls_version(node.value.value)
    
    res := build_result(node.value, parent.path, "Use of deprecated TLS/SSL protocol version")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    name_matches_keyword(node.name, cipher_suite_keywords)
    
    node.value.ir_type == "String"
    is_weak_cipher_pattern(node.value.value)
    
    res := build_result(node.value, parent.path, "Use of weak cipher pattern")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    name_matches_keyword(node.name, storage_encryption_keywords)
    
    node.value.ir_type == "Boolean"
    is_encryption_disabled(node.value.value)
    
    res := build_result(node.value, parent.path, "Encryption is explicitly disabled")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    name_matches_keyword(node.name, storage_encryption_keywords)
    
    node.value.ir_type == "String"
    is_weak_ssl_mode(node.value.value)
    
    res := build_result(node.value, parent.path, "Weak or disabled SSL/TLS enforcement")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    name_matches_keyword(node.name, key_size_keywords)
    
    node.value.ir_type == "Integer"
    is_weak_key_size(node.value.value)
    
    res := build_result(node.value, parent.path, "Use of insufficient key size")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    name_matches_keyword(node.name, key_size_keywords)
    
    node.value.ir_type == "String"
    lower_str(node.value.value) == "128"
    
    res := build_result(node.value, parent.path, "Use of insufficient key size (128 bits)")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    name_matches_keyword(node.name, cipher_suite_keywords)
    
    node.value.ir_type == "Array"
    any_string_in_args_weak(node.value, is_weak_algorithm_exact)
    
    res := build_result(node.value, parent.path, "Use of weak encryption algorithm in cipher suite array")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    name_matches_keyword(node.name, cipher_suite_keywords)
    
    node.value.ir_type == "Array"
    any_string_in_args_weak(node.value, is_weak_tls_version)
    
    res := build_result(node.value, parent.path, "Use of deprecated TLS version in cipher suite array")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    name_matches_keyword(node.name, cipher_suite_keywords)
    
    node.value.ir_type == "Array"
    any_string_in_args_weak(node.value, is_weak_cipher_pattern)
    
    res := build_result(node.value, parent.path, "Use of weak cipher pattern in cipher suite array")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    name_matches_keyword(node.name, certificate_keywords)
    
    node.value.ir_type == "String"
    is_weak_algorithm_exact(node.value.value)
    
    res := build_result(node.value, parent.path, "Use of weak algorithm in certificate")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Variable"
    name_matches_keyword(node.name, cipher_suite_keywords)
    
    node.value.ir_type == "String"
    is_weak_cipher_pattern(node.value.value)
    
    res := build_result(node.value, parent.path, "Use of weak cipher pattern in variable")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Variable"
    name_matches_keyword(node.name, encryption_key_keywords)
    
    node.value.ir_type == "String"
    is_weak_algorithm_exact(node.value.value)
    
    res := build_result(node.value, parent.path, "Use of weak encryption algorithm in variable")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Variable"
    name_matches_keyword(node.name, sensitive_data_keywords)
    
    node.value.ir_type == "Access"
    node.value.right.ir_type == "String"
    is_weak_algorithm_substring(node.value.right.value)
    
    res := build_result(node.value, parent.path, sprintf("Access to field with weak cryptographic reference: %s", [node.value.right.value]))
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Variable"
    name_matches_keyword(node.name, sensitive_data_keywords)
    
    node.value.ir_type == "Access"
    node.value.right.ir_type == "VariableReference"
    is_weak_algorithm_substring(node.value.right.value)
    
    res := build_result(node.value, parent.path, sprintf("Access to field with weak cryptographic reference: %s", [node.value.right.value]))
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "FunctionCall"
    func_name_indicates_weak(node.name)
    
    res := build_result(node, parent.path, "Use of weak or deprecated hash/encryption function")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "FunctionCall"
    any_string_in_args_weak(node.args, is_weak_algorithm_exact)
    
    res := build_result(node, parent.path, "Function call with weak cryptographic algorithm argument")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "FunctionCall"
    any_string_in_args_weak(node.args, is_weak_tls_version)
    
    res := build_result(node, parent.path, "Function call with weak TLS version argument")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "FunctionCall"
    any_string_in_args_weak(node.args, is_weak_cipher_pattern)
    
    res := build_result(node, parent.path, "Function call with weak cipher pattern argument")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "MethodCall"
    func_name_indicates_weak(node.method)
    
    res := build_result(node, parent.path, "Use of weak or deprecated hash/encryption method")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "MethodCall"
    any_string_in_args_weak(node.args, is_weak_algorithm_exact)
    
    res := build_result(node, parent.path, "Method call with weak cryptographic algorithm argument")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "MethodCall"
    any_string_in_args_weak(node.args, is_weak_tls_version)
    
    res := build_result(node, parent.path, "Method call with weak TLS version argument")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "MethodCall"
    any_string_in_args_weak(node.args, is_weak_cipher_pattern)
    
    res := build_result(node, parent.path, "Method call with weak cipher pattern argument")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    name_matches_keyword(node.name, secret_keywords)
    
    node.value.ir_type == "String"
    is_weak_algorithm_substring(node.value.value)
    
    res := build_result(node.value, parent.path, "Weak cryptographic algorithm reference in secret configuration")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    name_matches_keyword(node.name, network_encryption_keywords)
    
    node.value.ir_type == "String"
    is_weak_algorithm_exact(node.value.value)
    
    res := build_result(node.value, parent.path, "Use of weak encryption algorithm in network/VPN configuration")
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    name_matches_keyword(node.name, sensitive_data_keywords)
    
    node.value.ir_type == "Access"
    node.value.right.ir_type == "String"
    is_weak_algorithm_substring(node.value.right.value)
    
    res := build_result(node.value, parent.path, sprintf("Potential weak crypto in password/secret field: %s", [node.value.right.value]))
}

Glitch_Analysis[res] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    
    node.ir_type == "Attribute"
    name_matches_keyword(node.name, "cipher")
    
    node.value.ir_type == "Array"
    elem := node.value[_]
    elem.ir_type == "String"
    is_weak_cipher_pattern(elem.value)
    
    res := build_result(node.value, parent.path, "Weak cipher in configuration")
}