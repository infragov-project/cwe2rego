package glitch

import data.glitch_lib

weak_patterns := {"DES", "3DES", "RC4", "MD5", "SHA1", "1024", "128", "ECB", "fixed", "PKCS#5", "disabled", "SSLv2", "SSLv3", "TLS_1.0", "TLS_1.1", "Predefined-2016", "AES-128", "AES128", "RSA-1024", "ELBSecurityPolicy-2016-08"}

encryption_attributes := {"algorithm", "encryption_type", "cipher_suite", "hash_function", "key_length", "key_size", "bits", "encryption_key_bits", "mode", "initialization_vector", "padding", "authentication", "protocol", "ssl_policy", "encryption_version", "sse_algorithm", "encryption_algorithm", "encrypt", "auth_method", "auth_option"}

check_weak_pattern(node) {
    node.ir_type == "String"
    pattern := weak_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), node.value)
} else {
    node.ir_type == "FunctionCall"
    pattern := weak_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), node.name)
} else {
    node.ir_type == "FunctionCall"
    arg := node.args[_]
    check_weak_pattern(arg)
} else {
    node.ir_type == "Sum"
    check_weak_pattern(node.left) or check_weak_pattern(node.right)
} else {
    node.ir_type == "Access"
    check_weak_pattern(node.left) or check_weak_pattern(node.right)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower_name := lower(attr.name)
    encryption_attributes[lower_name]
    walk(attr.value, [_, node])
    check_weak_pattern(node)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak encryption configuration detected - Avoid using weak encryption algorithms, key lengths, modes, or protocols. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    lower_name := lower(var.name)
    encryption_attributes[lower_name]
    walk(var.value, [_, node])
    check_weak_pattern(node)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Weak encryption configuration detected - Avoid using weak encryption algorithms, key lengths, modes, or protocols. (CWE-326)"
    }
}