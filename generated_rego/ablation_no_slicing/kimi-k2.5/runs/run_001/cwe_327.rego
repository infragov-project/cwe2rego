package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC4", "RC2", "BLOWFISH", "TEA", "XTEA", "MD5", "MD4", "SHA1", "SHA-1", "MD2", "RIPEMD", "ECB", "MD5_CRYPT", "MD5-CRYPT", "CBC", "CBC_SHA", "CBC-SHA"}

weak_protocols := {"SSLV2", "SSLV3", "SSLV2.3", "TLSV1.0", "TLSV1.1", "TLS_1_0", "TLS_1_1", "TLS1.0", "TLS1.1"}

check_weak_string(str) {
    upper_val := upper(str)
    weak := weak_algorithms[_]
    contains(upper_val, weak)
}

check_weak_protocol(str) {
    upper_val := upper(str)
    protocol := weak_protocols[_]
    contains(upper_val, protocol)
}

contains(str, substr) {
    regex.match(sprintf(".*%s.*", [substr]), str)
}

is_encryption_related_attr(name) {
    lower_name := lower(name)
    regex.match(".*(encryption|encrypt|cipher|crypto|algorithm|hash|signature|ssl|tls|key|kms|sse|tde|cipher_suites|cipher_suite|protocol|auth_method|password).*", lower_name)
}

is_cipher_suite_attr(name) {
    regex.match("(?i).*(cipher_suites|cipher_suite).*", name)
}

get_func_name(node) = fname {
    node.ir_type == "FunctionCall"
    fname := node.name
}

get_func_name(node) = fname {
    node.ir_type == "MethodCall"
    fname := node.method
}

is_weak_hash_func(fname) {
    lower_fname := lower(fname)
    lower_fname == "md5"
}

is_weak_hash_func(fname) {
    lower_fname := lower(fname)
    lower_fname == "sha1"
}

is_hash_related_func(fname) {
    lower_fname := lower(fname)
    regex.match(".*(hash|md5|sha|digest|crypto|encrypt|cipher).*", lower_fname)
}

hash_func_has_weak_arg(node) {
    is_weak_hash_func(node.name)
    count(node.args) > 0
}

hash_func_has_weak_arg(node) {
    lower(node.name) == "filter|hash"
    arg := node.args[_]
    arg.ir_type == "String"
    check_weak_string(arg.value)
}

access_has_weak_key(node) {
    node.ir_type == "Access"
    node.right.ir_type == "String"
    check_weak_string(node.right.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    hash_func_has_weak_arg(node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak hash/encryption function call detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Access"
    access_has_weak_key(node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak cryptographic key reference detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    lower(entry.key.value) == "encrypt"
    entry.value.ir_type == "String"
    check_weak_string(entry.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": entry,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak encryption algorithm detected in encrypt key. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    is_encryption_related_attr(node.name)
    node.value.ir_type == "String"
    check_weak_string(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak cryptographic algorithm detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    regex.match("(?i).*(ssl|tls|protocol|version).*", node.name)
    node.value.ir_type == "String"
    check_weak_protocol(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak TLS/SSL protocol version detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Variable"
    is_encryption_related_attr(node.name)
    node.value.ir_type == "String"
    check_weak_string(node.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak cryptographic algorithm detected in variable. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    is_cipher_suite_attr(node.name)
    walk(node.value, [_, leaf])
    leaf.ir_type == "String"
    check_weak_string(leaf.value)
    result := {
        "type": "sec_weak_crypt",
        "element": leaf,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak cipher suite detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    check_weak_string(node.value)
    parent_node := [n | walk(parent, [p, n]); {"Attribute", "Variable"}[n.ir_type]; n.value == node][0]
    is_encryption_related_attr(parent_node.name)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak algorithm detected in encryption context. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    lower(node.name) == "password"
    node.value.ir_type == "Access"
    node.value.right.ir_type == "String"
    check_weak_string(node.value.right.value)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Weak password hash algorithm detected. (CWE-327)"
    }
}