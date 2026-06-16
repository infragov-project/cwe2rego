package glitch

import data.glitch_lib

weak_algorithms := {"DES", "3DES", "RC4", "MD5", "SHA1", "SHA-1", "SHA", "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "ECB", "WEP", "WPA", "md5_crypt", "sha1", "CBC"}

crypto_keywords := {"algorithm", "cipher", "encryption", "hash", "protocol", "key_length", "key_size", "bit_length", "encrypt", "decrypt", "ssl", "tls", "certificate", "cipher_suite", "crypto", "cryptographic", "password", "secret", "credential", "auth_method", "auth", "authentication"}

check_weak_algorithm(value) {
    value.ir_type == "String"
    weak_algorithm := weak_algorithms[_]
    regex.match(sprintf("(?i).*%s.*", [weak_algorithm]), value.value)
}

check_weak_algorithm(value) {
    value.ir_type == "Access"
    value.right.ir_type == "String"
    weak_algorithm := weak_algorithms[_]
    regex.match(sprintf("(?i).*%s.*", [weak_algorithm]), value.right.value)
}

check_weak_algorithm(value) {
    value.ir_type == "FunctionCall"
    weak_algorithm := weak_algorithms[_]
    regex.match(sprintf("(?i).*%s.*", [weak_algorithm]), value.name)
}

check_crypto_name(name) {
    crypto_keyword := crypto_keywords[_]
    regex.match(sprintf("(?i).*%s.*", [crypto_keyword]), name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    check_crypto_name(attr.name)
    check_weak_algorithm(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using broken or risky cryptographic algorithms as per CWE-327."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    check_crypto_name(var.name)
    check_weak_algorithm(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm - Avoid using broken or risky cryptographic algorithms as per CWE-327."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    check_weak_algorithm(node)
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm in function call - Avoid using broken or risky cryptographic algorithms as per CWE-327."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    arg := node.args[_]
    check_weak_algorithm(arg)
    result := {
        "type": "sec_weak_crypt",
        "element": arg,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm in function call argument - Avoid using broken or risky cryptographic algorithms as per CWE-327."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key_expr := pair.key
    key_expr.ir_type == "String"
    check_crypto_name(key_expr.value)
    value_expr := pair.value
    check_weak_algorithm(value_expr)
    result := {
        "type": "sec_weak_crypt",
        "element": value_expr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm in hash value - Avoid using broken or risky cryptographic algorithms as per CWE-327."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Array"
    element := node.value[_]
    element.ir_type == "Hash"
    pair := element.value[_]
    key_expr := pair.key
    key_expr.ir_type == "String"
    check_crypto_name(key_expr.value)
    value_expr := pair.value
    check_weak_algorithm(value_expr)
    result := {
        "type": "sec_weak_crypt",
        "element": value_expr,
        "path": parent.path,
        "description": "Use of broken or risky cryptographic algorithm in array element - Avoid using broken or risky cryptographic algorithms as per CWE-327."
    }
}