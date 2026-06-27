package glitch

import data.glitch_lib

password_patterns := {"password", "passwd", "pwd", "credentials", "credential", "secret_pass", "password_hash", "proxy_password", "secret", "token", "key", "passphrase"}

non_secret_key_patterns := {"access_key", "public_key", "gpg_key", "apt_key", "authorized_keys", "keyring", "private_key_file", "sslclientkey", "passphrase", "key_id", "signing_key"}

is_password_field(name) {
    lower_name := lower(name)
    pattern := password_patterns[_]
    contains(lower_name, pattern)
}

is_non_secret_key_field(name) {
    lower_name := lower(name)
    pattern := non_secret_key_patterns[_]
    contains(lower_name, pattern)
}

is_sensitive_field(name) {
    is_password_field(name)
    not is_non_secret_key_field(name)
}

is_empty_string(val) {
    val.ir_type == "String"
    val.value == ""
}

is_undef(val) {
    val.ir_type == "Undef"
}

is_null(val) {
    val.ir_type == "Null"
}

has_empty_value(val) {
    is_empty_string(val)
} else {
    is_undef(val)
} else {
    is_null(val)
}

get_last_key_from_access(node) = key {
    node.ir_type == "Access"
    get_last_key_from_access(node.right, key)
} else = key {
    node.ir_type == "String"
    key := node.value
} else = key {
    node.ir_type == "VariableReference"
    key := node.value
}

check_nested_for_sensitive_empty(val, path) {
    val.ir_type == "Hash"
    val.value[_].key.ir_type == "String"
    key_name := val.value[_].key.value
    is_sensitive_field(key_name)
    has_empty_value(val.value[_].value)
} else {
    val.ir_type == "Array"
    val.value[_]
    check_nested_for_sensitive_empty(val.value[_], path)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    is_sensitive_field(var.name)
    has_empty_value(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty or null password value - Password and credential fields should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Assign"
    
    name := get_last_key_from_access(node.left)
    is_sensitive_field(name)
    has_empty_value(node.right)
    
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty or null password value - Password and credential fields should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    is_sensitive_field(attr.name)
    has_empty_value(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty or null password value - Password and credential fields should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    unit_blocks := parent.unit_blocks[_]
    attrs := unit_blocks.attributes[_]
    
    is_sensitive_field(attrs.name)
    has_empty_value(attrs.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attrs,
        "path": parent.path,
        "description": "Empty or null password value - Password and credential fields should not be empty or null. (CWE-258)"
    }
}