package glitch

import data.glitch_lib

binding_attributes := {"ip", "host", "bind_address", "listen_address", "bind", "listenaddr", "bind_ip", "server_address", "listen_on", "addr"}
unrestricted_ips := {"0.0.0.0", "*"}

check_binding_attr(key) {
    key == "ip"
} else {
    key == "host"
} else {
    key == "bind_address"
} else {
    key == "listen_address"
} else {
    key == "bind"
} else {
    key == "listenaddr"
} else {
    key == "bind_ip"
} else {
    key == "server_address"
} else {
    key == "listen_on"
} else {
    key == "addr"
}

check_unrestricted(value) {
    value == "0.0.0.0"
} else {
    value == "*"
}

get_key_string(key_node) = str {
    key_node.ir_type == "String"
    str := key_node.value
} else {
    key_node.ir_type == "VariableReference"
    str := key_node.value
} else {
    str := key_node.code
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    var.value.ir_type == "String"
    check_unrestricted(var.value.value)
    
    var_name_lower := lower(var.name)
    attr_found := false
    attr_found = {attr | attr := binding_attributes[_]; contains(var_name_lower, attr)} != set()
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Variable name contains binding attribute and value is unrestricted IP. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    walk(var.value, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    
    key_str := get_key_string(pair.key)
    normalized_key := lower(key_str)
    normalized_key := replace(normalized_key, ":", "")
    check_binding_attr(normalized_key)
    
    pair.value.ir_type == "String"
    check_unrestricted(pair.value.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Variable hash contains binding attribute with unrestricted IP. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr_name_lower := lower(attr.name)
    attr_name_normalized := replace(attr_name_lower, ":", "")
    check_binding_attr(attr_name_normalized)
    
    attr.value.ir_type == "String"
    check_unrestricted(attr.value.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Atomic unit attribute binds to unrestricted IP. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    walk(attr.value, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    
    key_str := get_key_string(pair.key)
    normalized_key := lower(key_str)
    normalized_key := replace(normalized_key, ":", "")
    check_binding_attr(normalized_key)
    
    pair.value.ir_type == "String"
    check_unrestricted(pair.value.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Atomic unit attribute hash contains binding attribute with unrestricted IP. (CWE-1327)"
    }
}