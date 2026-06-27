package glitch

import data.glitch_lib

weak_algorithms := {"des", "3des", "rc2", "rc4", "rc5", "idea", "seed", "md5", "sha1", "sha-1", "md5crypt", "sha1crypt", "descrypt", "des_crypt", "md5_crypt", "sha1_crypt", "ecdsa", "ecb", "cbc", "rc4_hmac", "hmacmd5", "hmac-sha1", "none", "no-encryption", "plaintext", "unencrypted", "custom", "proprietary", "homegrown", "internal", "legacy", "hmacmd5"}

weak_tls := {"tlsv1.0", "tlsv1.1", "sslv3", "tls1.0", "tls1.1", "ssl2", "ssl3", "tlsv1", "sslv2", "tls1"}

crypto_keywords := {"encrypt", "cipher", "algorithm", "crypto", "hash", "digest", "ssl", "tls", "mode", "protocol", "kdf", "pbkdf2", "scrypt", "bcrypt", "aes", "rsa", "dsa", "ec", "cipher_suite", "cipher_suites", "server_encryption_options", "client_encryption_options"}

weak_crypto_patterns := {"des", "3des", "rc2", "rc4", "rc5", "md5", "sha1", "sha-1", "ecb", "hmacmd5", "hmac-sha1", "md5crypt", "sha1crypt", "descrypt", "cbc", "hmacmd5"}

lowercase(s) = lower(s)

contains_substring(str, substr) {
    contains(lowercase(str), substr)
}

is_weak_algorithm(strval) {
    weak_algorithms[lowercase(strval)]
}

is_weak_algorithm(strval) {
    weak_tls[lowercase(strval)]
}

is_weak_algorithm_pattern(strval) {
    pattern := weak_crypto_patterns[_]
    contains_substring(strval, pattern)
}

is_crypto_related(name) {
    keyword := crypto_keywords[_]
    contains_substring(name, keyword)
}

get_string_value(expr) = value {
    expr.ir_type == "String"
    value := expr.value
}

get_string_value(expr) = value {
    expr.ir_type == "VariableReference"
    value := expr.value
}

stringify_expr(expr) = str {
    expr.ir_type == "String"
    str := expr.value
} else = str {
    expr.ir_type == "VariableReference"
    str := expr.value
} else = str {
    expr.ir_type == "Integer"
    str := sprintf("%d", [expr.value])
} else = str {
    str := ""
}

expr_is_weak_algorithm(expr) {
    strval := get_string_value(expr)
    strval != ""
    is_weak_algorithm(strval)
}

expr_is_weak_algorithm(expr) {
    strval := stringify_expr(expr)
    strval != ""
    is_weak_algorithm_pattern(strval)
}

expr_has_weak_algorithm_in_nested(expr) {
    walk(expr, [_, node])
    expr_is_weak_algorithm(node)
}

shell_cmd_has_weak_algo(expr) {
    expr.ir_type == "String"
    cmd := expr.value
    parts := split(cmd, " ")
    part := parts[_]
    is_weak_algorithm(part)
}

is_md5_function_call(expr) {
    expr.ir_type == "FunctionCall"
    lowercase(expr.name) == "md5"
}

is_cipher_suites_attribute(name) {
    lower_name := lowercase(name)
    contains(lower_name, "cipher_suite")
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, elem])
    elem.ir_type == "Attribute"
    
    is_crypto_related(elem.name)
    
    expr_has_weak_algorithm_in_nested(elem.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": elem,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic configuration detected in attribute. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, elem])
    elem.ir_type == "Variable"
    
    is_crypto_related(elem.name)
    
    expr_has_weak_algorithm_in_nested(elem.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": elem,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic configuration detected in variable. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, elem])
    elem.ir_type == "Attribute"
    
    is_cipher_suites_attribute(elem.name)
    
    elem.value.ir_type == "String"
    value_str := elem.value.value
    contains_substring(value_str, "cbc")
    
    result := {
        "type": "sec_weak_crypt",
        "element": elem,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher suite with CBC mode detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, elem])
    elem.ir_type == "Variable"
    
    is_cipher_suites_attribute(elem.name)
    
    elem.value.ir_type == "String"
    value_str := elem.value.value
    contains_substring(value_str, "cbc")
    
    result := {
        "type": "sec_weak_crypt",
        "element": elem,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher suite with CBC mode detected. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, elem])
    elem.ir_type == "Variable"
    
    is_md5_function_call(elem.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": elem,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak MD5 function used for cryptographic operation. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, elem])
    elem.ir_type == "Attribute"
    
    lower_name := lowercase(elem.name)
    lower_name == "shell"
    
    shell_cmd_has_weak_algo(elem.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": elem,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cryptographic algorithm in shell command. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, elem])
    elem.ir_type == "FunctionCall"
    
    func_name := lowercase(elem.name)
    contains_substring(func_name, "encrypt")
    
    arg := elem.args[_]
    strval := get_string_value(arg)
    is_weak_algorithm(strval)
    
    result := {
        "type": "sec_weak_crypt",
        "element": elem,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak algorithm in cryptographic function call. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, elem])
    elem.ir_type == "MethodCall"
    
    method_name := lowercase(elem.method)
    contains_substring(method_name, "encrypt")
    
    arg := elem.args[_]
    strval := get_string_value(arg)
    is_weak_algorithm(strval)
    
    result := {
        "type": "sec_weak_crypt",
        "element": elem,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak algorithm in cryptographic method call. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, elem])
    elem.ir_type == "FunctionCall"
    
    func_name := lowercase(elem.name)
    contains_substring(func_name, "hash")
    
    arg := elem.args[_]
    strval := get_string_value(arg)
    is_weak_algorithm(strval)
    
    result := {
        "type": "sec_weak_crypt",
        "element": elem,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak hash algorithm in filter function. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, elem])
    elem.ir_type == "Hash"
    
    entry := elem.value[_]
    key_str := stringify_expr(entry.key)
    
    is_cipher_suites_attribute(key_str)
    
    val_str := stringify_expr(entry.value)
    contains_substring(val_str, "cbc")
    
    result := {
        "type": "sec_weak_crypt",
        "element": entry,
        "path": parent.path,
        "description": "Inadequate Encryption Strength - Weak cipher suite configuration in hash. (CWE-326)"
    }
}