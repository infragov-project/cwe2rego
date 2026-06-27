package glitch

import data.glitch_lib

weak_encryption_algorithms := {"DES", "3DES", "RC2", "RC4", "MD5", "SHA1", "SHA-1", "RIPEMD", "MD4", "MD2"}

weak_ciphers := {"ECB", "NULL", "EXPORT"}

weak_tls_versions := {"TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2", "TLS1.0", "TLS1.1", "TLSv1", "TLS1"}

crypto_attr_patterns := {"encryption", "algorithm", "cipher", "tls_version", "min_tls_version", "ssl_policy", "protocol", "signing_algorithm", "key_spec", "hash", "crypto", "password", "digest"}

weak_crypto_in_string(str) {
    upper_str := upper(str)
    weak := weak_encryption_algorithms[_]
    contains(upper_str, weak)
}

weak_crypto_in_string(str) {
    upper_str := upper(str)
    weak := weak_ciphers[_]
    contains(upper_str, weak)
}

weak_crypto_in_string(str) {
    weak_tls_versions[str]
}

is_crypto_related_attr(name) {
    lower_name := lower(name)
    pattern := crypto_attr_patterns[_]
    contains(lower_name, pattern)
}

check_value_recursive(val) {
    val.ir_type == "String"
    weak_crypto_in_string(val.value)
}

check_value_recursive(val) {
    val.ir_type == "VariableReference"
    weak_crypto_in_string(val.value)
}

check_value_recursive(val) {
    val.ir_type == "Integer"
    str := sprintf("%d", [val.value])
    weak_crypto_in_string(str)
}

check_function_call_weak(call) {
    name := lower(call.name)
    contains(name, "md5")
    not contains(name, "hmac")
}

check_function_call_weak(call) {
    name := lower(call.name)
    contains(name, "sha1")
    not contains(name, "hmac")
}

check_value_recursive(val) {
    val.ir_type == "FunctionCall"
    check_function_call_weak(val)
}

check_value_recursive(val) {
    val.ir_type == "MethodCall"
    check_function_call_weak(val)
}

check_value_recursive(val) {
    val.ir_type == "Access"
    walk(val, [_, n])
    n.ir_type == "String"
    weak_crypto_in_string(n.value)
}

check_value_in_array(val) {
    val.ir_type == "Array"
    item := val.value[_]
    check_value_recursive(item)
}

check_value_in_array(val) {
    val.ir_type == "Array"
    item := val.value[_]
    check_value_in_hash(item)
}

check_value_in_hash(val) {
    val.ir_type == "Hash"
    pair := val.value[_]
    check_value_recursive(pair.value)
}

check_value_in_hash(val) {
    val.ir_type == "Hash"
    pair := val.value[_]
    check_value_nested(pair.value)
}

check_value_nested(val) {
    check_value_in_array(val)
}

check_value_nested(val) {
    check_value_in_hash(val)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    is_crypto_related_attr(attr.name)
    check_value_recursive(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using weak or deprecated cryptographic algorithms, protocols, or key sizes. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_crypto_related_attr(var.name)
    check_value_recursive(var.value)

    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Avoid using weak or deprecated cryptographic algorithms, protocols, or key sizes. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    is_crypto_related_attr(attr.name)
    check_value_in_array(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak cryptography detected in collection values. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    is_crypto_related_attr(attr.name)
    check_value_in_hash(attr.value)

    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak cryptography detected in hash values. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    name := lower(node.name)
    contains(name, "md5")
    not contains(name, "hmac")

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - MD5 hash function detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    name := lower(node.name)
    contains(name, "sha1")
    not contains(name, "hmac")

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - SHA1 hash function detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Access"
    node.right.ir_type == "String"
    key_name := lower(node.right.value)
    contains(key_name, "password")
    contains(key_name, "md5")

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Access to MD5 password hash detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Access"
    node.right.ir_type == "String"
    key_name := lower(node.right.value)
    contains(key_name, "password")
    contains(key_name, "sha1")

    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Access to SHA1 password hash detected. (CWE-327)"
    }
}