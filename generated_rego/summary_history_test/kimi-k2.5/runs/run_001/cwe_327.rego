package glitch

import data.glitch_lib

weak_algorithms := {"des", "3des", "rc4", "rc2", "blowfish", "md5", "md2", "md4", "sha1", "sha-1", "sha-0", "sha0", "ripemd", "ripemd160", "ripemd-160", "dsa", "hmacmd5", "hmac-sha1"}

weak_tls_versions := {"sslv2", "sslv3", "tlsv1.0", "tlsv1.1", "tls1.0", "tls1.1", "ssl2", "ssl3", "1.0", "1.1", "v1.0", "v1.1"}

weak_cipher_indicators := {"_cbc_", "_ecb_", "_rc4_", "_des_", "_3des_", "md5", "sha1", "sha-1", "hmacmd5"}

insecure_crypto_values := {"md5_crypt", "des_crypt", "sha1_crypt"}

has_weak_crypto_pattern(str) {
    lower_str := lower(str)
    alg := weak_algorithms[_]
    contains(lower_str, alg)
}

has_weak_crypto_pattern(str) {
    lower_str := lower(str)
    ver := weak_tls_versions[_]
    contains(lower_str, ver)
}

has_weak_crypto_pattern(str) {
    lower_str := lower(str)
    indicator := weak_cipher_indicators[_]
    contains(lower_str, indicator)
}

has_weak_crypto_pattern(str) {
    lower_str := lower(str)
    val := insecure_crypto_values[_]
    lower_str == val
}

get_string_value(node) = val {
    node.ir_type == "String"
    val = node.value
}

get_string_value(node) = val {
    node.ir_type == "VariableReference"
    val = node.value
}

is_crypto_variable_name(name) {
    name_lower := lower(name)
    regex.match(".*(cipher_suites|encryption|cipher|crypto|hash|algorithm|auth_method|digest|password|suites|method|protocol|mode|version|ssl|tls|encrypt|auth).*", name_lower)
}

is_weak_crypto_function_name(name) {
    lower_name := lower(name)
    contains(lower_name, "md5")
}

is_weak_crypto_function_name(name) {
    lower_name := lower(name)
    contains(lower_name, "sha1")
}

check_string_weak_crypto(val) {
    has_weak_crypto_pattern(val)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    node := vars[_]
    
    is_crypto_variable_name(node.name)
    
    walk(node.value, [_, child])
    child.ir_type == "String"
    check_string_weak_crypto(child.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak cryptographic algorithm detected. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    node := vars[_]
    
    walk(node, [_, child])
    child.ir_type == "FunctionCall"
    is_weak_crypto_function_name(child.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak cryptographic function call. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    node := attrs[_]
    
    is_crypto_variable_name(node.name)
    
    walk(node.value, [_, child])
    child.ir_type == "String"
    check_string_weak_crypto(child.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak cryptographic configuration in attribute. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.name == "encrypt"
    
    walk(node.value, [_, child])
    child.ir_type == "String"
    check_string_weak_crypto(child.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak encryption algorithm in encrypt attribute. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.name == "encrypt"
    
    walk(node.value, [_, child])
    child.ir_type == "String"
    check_string_weak_crypto(child.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak encryption algorithm in encrypt variable. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Hash"
    
    entry := node.value[_]
    entry_key := entry.key.value
    entry_key == "encrypt"
    
    walk(entry.value, [_, child])
    child.ir_type == "String"
    check_string_weak_crypto(child.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": entry,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak encryption algorithm in hash entry. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conds := glitch_lib.all_conditional_statements(parent)
    cond := conds[_]
    
    walk(cond, [_, node])
    node.ir_type == "Variable"
    is_crypto_variable_name(node.name)
    
    walk(node.value, [_, child])
    child.ir_type == "String"
    check_string_weak_crypto(child.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak cryptographic algorithm in conditional block. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    is_weak_crypto_function_name(node.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak cryptographic function call. (CWE-327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    
    arg := node.args[_]
    arg.ir_type == "String"
    check_string_weak_crypto(arg.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": "Use of a Broken or Risky Cryptographic Algorithm - Weak cryptographic algorithm in function argument. (CWE-327)"
    }
}