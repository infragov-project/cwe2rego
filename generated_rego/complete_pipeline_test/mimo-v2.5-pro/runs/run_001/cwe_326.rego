package glitch

import data.glitch_lib

weak_algo_patterns := {"3des", "rc4", "rc2", "ssl2", "ssl3", "tls1.0", "tls1.1", "tlsv1.0", "tlsv1.1", "md5", "sha1", "md5_crypt", "cbc"}

crypto_keywords := {"algorithm", "cipher", "encrypt", "hash", "digest", "signature", "ssl", "tls", "key_size", "key_length", "rsa_bits", "dh_param", "auth", "password", "secret"}

algo_keywords := {"algorithm", "cipher", "protocol", "digest", "signature"}

encryption_flag_names := {"encryption_at_rest", "encryption_in_transit", "https_only", "force_ssl", "enforce_tls", "require_ssl"}

key_size_names := {"key_size", "key_length", "rsa_bits", "dh_param", "master_key_length", "data_key_length"}

has_weak_algo_in_string(val) {
    lower_val := lower(val)
    s := weak_algo_patterns[_]
    glitch_lib.contains(lower_val, s)
}

has_crypto_keyword(name) {
    lower_name := lower(name)
    k := crypto_keywords[_]
    glitch_lib.contains(lower_name, k)
}

has_algo_keyword(name) {
    lower_name := lower(name)
    k := algo_keywords[_]
    glitch_lib.contains(lower_name, k)
}

any_weak_algo_in_value(node) {
    walk(node, [_, s])
    s.ir_type == "String"
    has_weak_algo_in_string(s.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, fc])
    fc.ir_type == "FunctionCall"
    has_weak_algo_in_string(fc.name)
    result := {
        "type": "sec_weak_crypt",
        "element": fc,
        "path": parent.path,
        "description": "Weak cryptographic algorithm detected in function call name - Use strong cryptographic algorithms. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, fc])
    fc.ir_type == "FunctionCall"
    arg := fc.args[_]
    arg.ir_type == "String"
    has_weak_algo_in_string(arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": fc,
        "path": parent.path,
        "description": sprintf("Weak cryptographic algorithm '%s' detected in function call arguments - Use strong cryptographic algorithms. (CWE-326)", [arg.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, mc])
    mc.ir_type == "MethodCall"
    has_weak_algo_in_string(mc.method)
    result := {
        "type": "sec_weak_crypt",
        "element": mc,
        "path": parent.path,
        "description": "Weak cryptographic algorithm detected in method call - Use strong cryptographic algorithms. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, mc])
    mc.ir_type == "MethodCall"
    arg := mc.args[_]
    arg.ir_type == "String"
    has_weak_algo_in_string(arg.value)
    result := {
        "type": "sec_weak_crypt",
        "element": mc,
        "path": parent.path,
        "description": sprintf("Weak cryptographic algorithm '%s' detected in method call arguments - Use strong cryptographic algorithms. (CWE-326)", [arg.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    has_crypto_keyword(attr.name)
    any_weak_algo_in_value(attr.value)
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Weak cryptographic algorithm detected in '%s' - Use strong cryptographic algorithms. (CWE-326)", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    has_algo_keyword(attr.name)
    attr.value.ir_type == "String"
    lower(attr.value.value) == {"none", "null", "plaintext"}[_]
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Weak cryptographic setting detected in '%s' - Use strong cryptographic algorithms. (CWE-326)", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    kv := hash_node.value[_]
    kv.key.ir_type == "String"
    has_crypto_keyword(kv.key.value)
    kv.value.ir_type == "String"
    has_weak_algo_in_string(kv.value.value)
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": sprintf("Weak cryptographic algorithm detected for '%s' - Use strong cryptographic algorithms. (CWE-326)", [kv.key.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, var])
    var.ir_type == "Variable"
    has_crypto_keyword(var.name)
    any_weak_algo_in_value(var.value)
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": sprintf("Weak cryptographic algorithm detected in variable '%s' - Use strong cryptographic algorithms. (CWE-326)", [var.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    kv.ir_type == "Attribute"
    encryption_flag_names[_] == lower(kv.name)
    kv.value.ir_type == "Boolean"
    kv.value.value == false
    result := {
        "type": "sec_weak_crypt",
        "element": kv,
        "path": parent.path,
        "description": sprintf("Encryption disabled in '%s' - Enable encryption for data protection. (CWE-326)", [kv.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    key_size_names[_] == lower(attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value < 2048
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Insufficient key size (%d bits) in '%s' - Use at least 2048-bit keys. (CWE-326)", [attr.value.value, attr.name])
    }
}