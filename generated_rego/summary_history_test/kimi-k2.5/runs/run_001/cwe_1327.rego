package glitch

import data.glitch_lib

unrestricted_ipv4 := {"0.0.0.0", "0.0/0", "*", "all", "any"}
unrestricted_ipv6 := {"::", "::0", "::/0", "[::]", "[::0]"}
bind_address_keywords := {"listen", "bind", "address", "ip", "host", "interface", "endpoint", "socket", "iface", "allowed", "permitted", "client", "source", "net", "addr"}

is_unrestricted_address(str) {
    lower_str := lower(str)
    unrestricted_ipv4[lower_str]
} else {
    unrestricted_ipv6[str]
}

has_bind_keyword(name) {
    lower_name := lower(name)
    keyword := bind_address_keywords[_]
    contains(lower_name, keyword)
}

check_string_unrestricted(node) {
    node.ir_type == "String"
    is_unrestricted_address(node.value)
}

walk_hash_step[val] {
    walk(input, [path, n])
    n.ir_type == "Hash"
    key_val := n.value[_]
    key_val.key.ir_type == "String"
    has_bind_keyword(key_val.key.value)
    val := key_val.value
}

walk_hash_step[val] {
    walk(input, [path, n])
    n.ir_type == "Hash"
    key_val := n.value[_]
    key_val.key.ir_type == "VariableReference"
    has_bind_keyword(key_val.key.value)
    val := key_val.value
}

find_hash_binding = result {
    walk_hash_step[target]
    target.ir_type == "String"
    check_string_unrestricted(target)
    result := target
}

find_hash_binding = result {
    walk_hash_step[target]
    target.ir_type == "Array"
    item := target.value[_]
    item.ir_type == "String"
    is_unrestricted_address(item.value)
    result := item
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    has_bind_keyword(var.name)
    check_string_unrestricted(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Network-facing resources should not bind to 0.0.0.0, ::, or wildcard addresses allowing unrestricted remote access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    walk(var.value, [_, n])
    n.ir_type == "Hash"
    key_val := n.value[_]
    has_bind_key(key_val.key)
    
    child_val := key_val.value
    child_val.ir_type == "String"
    is_unrestricted_address(child_val.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": key_val,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Network-facing resources should not bind to 0.0.0.0, ::, or wildcard addresses allowing unrestricted remote access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    walk(var.value, [_, n])
    n.ir_type == "Hash"
    key_val := n.value[_]
    has_bind_key(key_val.key)
    
    child_val := key_val.value
    child_val.ir_type == "Array"
    item := child_val.value[_]
    item.ir_type == "String"
    is_unrestricted_address(item.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": key_val,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Network-facing resources should not bind to 0.0.0.0, ::, or wildcard addresses allowing unrestricted remote access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    has_bind_keyword(attr.name)
    check_string_unrestricted(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Network-facing resources should not bind to 0.0.0.0, ::, or wildcard addresses allowing unrestricted remote access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    walk(attr.value, [_, n])
    n.ir_type == "Hash"
    key_val := n.value[_]
    has_bind_key(key_val.key)
    
    child_val := key_val.value
    child_val.ir_type == "String"
    is_unrestricted_address(child_val.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": key_val,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Network-facing resources should not bind to 0.0.0.0, ::, or wildcard addresses allowing unrestricted remote access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    walk(attr.value, [_, n])
    n.ir_type == "Hash"
    key_val := n.value[_]
    has_bind_key(key_val.key)
    
    child_val := key_val.value
    child_val.ir_type == "Array"
    item := child_val.value[_]
    item.ir_type == "String"
    is_unrestricted_address(item.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": key_val,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Network-facing resources should not bind to 0.0.0.0, ::, or wildcard addresses allowing unrestricted remote access. (CWE-1327)"
    }
}

has_bind_key(node) {
    node.ir_type == "String"
    has_bind_keyword(node.value)
}

has_bind_key(node) {
    node.ir_type == "VariableReference"
    has_bind_keyword(node.value)
}