package glitch

import data.glitch_lib

weak_crypto_values := {"sha1", "md5", "md5_crypt", "des", "3des", "rc4", "ecb", "sslv2", "sslv3", "tlsv1.0", "tlsv1.1"}

strong_crypto_values := {"aes-256-cbc", "aes-256-gcm", "tlsv1.2", "tlsv1.3"}

contains(str, substr) {
    regex.match(sprintf("(?i).*%s.*", [substr]), str)
}

is_weak_crypto(value) {
    is_string(value)
    lower_value := lower(value)
    weak := weak_crypto_values[_]
    contains(lower_value, weak)
    not any(strong_crypto_values, strong, contains(lower_value, strong))
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.value.ir_type == "String"
    is_weak_crypto(attr.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Inadequate Encryption Strength - Weak encryption algorithm/protocol '%s' detected. (CWE-326)", [attr.value.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    func := attr.value
    func.ir_type == "FunctionCall"
    is_weak_crypto(func.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Inadequate Encryption Strength - Weak encryption function '%s' detected. (CWE-326)", [func.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    func := attr.value
    func.ir_type == "FunctionCall"
    
    arg := func.args[_]
    arg.ir_type == "String"
    is_weak_crypto(arg.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Inadequate Encryption Strength - Weak encryption algorithm/protocol '%s' detected. (CWE-326)", [arg.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Variable"
    
    node.value.ir_type == "String"
    is_weak_crypto(node.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Inadequate Encryption Strength - Weak encryption algorithm/protocol '%s' detected. (CWE-326)", [node.value.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Variable"
    
    func := node.value
    func.ir_type == "FunctionCall"
    is_weak_crypto(func.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Inadequate Encryption Strength - Weak encryption function '%s' detected. (CWE-326)", [func.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    pair := node.value[_]
    pair.value.ir_type == "String"
    is_weak_crypto(pair.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Inadequate Encryption Strength - Weak encryption algorithm/protocol '%s' detected. (CWE-326)", [pair.value.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    pair := node.value[_]
    func := pair.value
    func.ir_type == "FunctionCall"
    is_weak_crypto(func.name)
    
    result := {
        "type": "sec_weak_crypt",
        "element": node,
        "path": parent.path,
        "description": sprintf("Inadequate Encryption Strength - Weak encryption function '%s' detected. (CWE-326)", [func.name])
    }
}