package glitch

import data.glitch_lib

is_bind_address_name(name) {
    regex.match("(?i).*bind.*", name)
} else {
    regex.match("(?i).*listen.*", name)
} else {
    regex.match("(?i).*ip.*", name)
} else {
    regex.match("(?i).*addr.*", name)
} else {
    regex.match("(?i).*address.*", name)
}

is_unrestricted_ip(value) {
    value == "0.0.0.0"
} else {
    value == "[::]"
} else {
    value == "::"
} else {
    value == "::/0"
} else {
    value == "0000:0000:0000:0000:0000:0000:0000:0000"
}

has_unrestricted_ip(node) {
    walk(node, [_, n])
    n.ir_type == "String"
    is_unrestricted_ip(n.value)
}

get_key_name(key) = name {
    key.ir_type == "String"
    name := key.value
} else = name {
    key.ir_type == "VariableReference"
    name := key.value
}

find_bind_kv_pair(node) = result {
    walk(node, [_, n])
    n.ir_type == "Hash"
    kv := n.value[_]
    key_name := get_key_name(kv.key)
    is_bind_address_name(key_name)
    has_unrestricted_ip(kv.value)
    result := kv
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Variable"
    is_bind_address_name(node.name)
    has_unrestricted_ip(node.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Assigning 0.0.0.0 or :: as bind address exposes the service to all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Variable"
    bind_kv := find_bind_kv_pair(node.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": bind_kv,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Assigning 0.0.0.0 or :: as bind address exposes the service to all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_bind_address_name(attr.name)
    has_unrestricted_ip(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Assigning 0.0.0.0 or :: as bind address exposes the service to all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    bind_kv := find_bind_kv_pair(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": bind_kv,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Assigning 0.0.0.0 or :: as bind address exposes the service to all network interfaces. (CWE-1327)"
    }
}