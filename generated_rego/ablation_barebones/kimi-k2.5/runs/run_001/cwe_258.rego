package glitch

import data.glitch_lib

password_patterns := ["password", "passwd", "pwd", "pass"]

is_password_related(name) {
    lower_name := lower(name)
    pattern := password_patterns[_]
    regex.match(sprintf(".*%s.*", [pattern]), lower_name)
}

is_empty_password_value(value) {
    value.ir_type == "String"
    count(value.value) == 0
} else {
    value.ir_type == "Null"
}

has_empty_password_attribute(attrs) {
    attr := attrs[_]
    is_password_related(attr.name)
    is_empty_password_value(attr.value)
}

check_hash_empty_password(node) {
    node.ir_type == "Hash"
    kv := node.value[_]
    is_password_related(kv.name)
    is_empty_password_value(kv.value)
}

check_array_items_empty_password(node) {
    node.ir_type == "Array"
    item := node.value[_]
    item.ir_type == "Hash"
    kv := item.value[_]
    is_password_related(kv.name)
    is_empty_password_value(kv.value)
}

check_atomic_unit_empty_password(node) {
    attrs := glitch_lib.all_attributes(node)
    has_empty_password_attribute(attrs)
} else {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    check_hash_empty_password(attr.value)
} else {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    check_array_items_empty_password(attr.value)
}

check_variable_empty_password(var) {
    is_password_related(var.name)
    is_empty_password_value(var.value)
} else {
    is_password_related(var.name)
    check_hash_empty_password(var.value)
} else {
    is_password_related(var.name)
    check_array_items_empty_password(var.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    check_atomic_unit_empty_password(au)
    
    result := {
        "type": "sec_empty_pass",
        "element": au,
        "path": parent.path,
        "description": "Empty password in configuration - Using an empty string as a password is insecure. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    check_variable_empty_password(var)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration - Using an empty string as a password is insecure. (CWE-258)"
    }
}