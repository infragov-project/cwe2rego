package glitch

import data.glitch_lib

password_exact_keywords := {"password", "passwd", "pwd", "secret", "passphrase", "credential", "auth_token", "api_key", "api_secret", "access_key", "secret_key", "private_key", "encryption_key", "master_password", "admin_password", "root_password", "service_password", "database_password", "db_password", "ldap_password", "smtp_password"}

is_password_field(name) {
    lower_name := lower(name)
    some pwd_key
    password_exact_keywords[pwd_key]
    patterns := [
        sprintf("^%s$", [pwd_key]),
        sprintf("^.*_%s$", [pwd_key]),
        sprintf("^%s_.*$", [pwd_key]),
        sprintf("^.*_%s_.*$", [pwd_key])
    ]
    some pattern
    regex.match(pattern, lower_name)
}

is_empty_value(value) {
    value.ir_type == "String"
    count(trim_space(value.value)) == 0
}

is_empty_value(value) {
    value.ir_type == "Null"
}

is_empty_value(value) {
    value.ir_type == "Undef"
}

has_sensitive_parent_context(node_name) {
    parent_patterns := {"password", "secret", "credential", "auth", "login"}
    lower_name := lower(node_name)
    some pattern
    parent_patterns[pattern]
    contains(lower_name, pattern)
    is_password_field(node_name)
}

detect_empty_password_keyval(node) {
    is_password_field(node.name)
    is_empty_value(node.value)
    has_sensitive_parent_context(node.name)
}

find_empty_password_in_hash(hash_node, found_key, found_val) {
    hash_node.ir_type == "Hash"
    some pair
    walk(hash_node.value, [_, pair])
    is_object(pair)
    pair[_].ir_type == "String"
    key_node := pair[0]
    val_node := pair[1]
    is_password_field(key_node.value)
    is_empty_value(val_node)
    has_sensitive_parent_context(key_node.value)
    found_key = key_node
    found_val = val_node
}

contains(str, substr) {
    contains(str, substr)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    detect_empty_password_keyval(var)
    result := {
        "type": "sec_empty_pass",
        "element": var.value,
        "path": parent.path,
        "description": "Empty password in configuration file - Password or credential fields should not be assigned empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    aus := glitch_lib.all_atomic_units(parent)
    au := aus[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    detect_empty_password_keyval(attr)
    result := {
        "type": "sec_empty_pass",
        "element": attr.value,
        "path": parent.path,
        "description": "Empty password in configuration file - Password or credential fields should not be assigned empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := parent.attributes[_]
    detect_empty_password_keyval(attr)
    result := {
        "type": "sec_empty_pass",
        "element": attr.value,
        "path": parent.path,
        "description": "Empty password in configuration file - Password or credential fields should not be assigned empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Hash"
    find_empty_password_in_hash(var.value, _, val_node)
    result := {
        "type": "sec_empty_pass",
        "element": val_node,
        "path": parent.path,
        "description": "Empty password in configuration file - Password or credential fields should not be assigned empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    var.value.ir_type == "Array"
    some elem
    walk(var.value, [_, elem])
    find_empty_password_in_hash(elem, _, val_node)
    result := {
        "type": "sec_empty_pass",
        "element": val_node,
        "path": parent.path,
        "description": "Empty password in configuration file - Password or credential fields should not be assigned empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    aus := glitch_lib.all_atomic_units(parent)
    au := aus[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    attr.value.ir_type == "Hash"
    find_empty_password_in_hash(attr.value, _, val_node)
    result := {
        "type": "sec_empty_pass",
        "element": val_node,
        "path": parent.path,
        "description": "Empty password in configuration file - Password or credential fields should not be assigned empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    aus := glitch_lib.all_atomic_units(parent)
    au := aus[_]
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    some elem
    walk(attr.value, [_, elem])
    find_empty_password_in_hash(elem, _, val_node)
    result := {
        "type": "sec_empty_pass",
        "element": val_node,
        "path": parent.path,
        "description": "Empty password in configuration file - Password or credential fields should not be assigned empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := parent.attributes[_]
    attr.value.ir_type == "Hash"
    find_empty_password_in_hash(attr.value, _, val_node)
    result := {
        "type": "sec_empty_pass",
        "element": val_node,
        "path": parent.path,
        "description": "Empty password in configuration file - Password or credential fields should not be assigned empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := parent.attributes[_]
    attr.value.ir_type == "Array"
    some elem
    walk(attr.value, [_, elem])
    find_empty_password_in_hash(elem, _, val_node)
    result := {
        "type": "sec_empty_pass",
        "element": val_node,
        "path": parent.path,
        "description": "Empty password in configuration file - Password or credential fields should not be assigned empty values. (CWE-258)"
    }
}