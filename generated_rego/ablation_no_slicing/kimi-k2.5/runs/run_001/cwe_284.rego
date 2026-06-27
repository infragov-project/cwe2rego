package glitch

import data.glitch_lib

suspicious_network_values := {"0.0.0.0", "0.0.0.0/0", "::/0"}

network_related_names := {"bindip", "bind_ip", "bindaddress", "bind_address", "listen", "host", "ip", "bind", "net_bind_ip", "net_bindip", "mongod_bind_ip", "mysql_bind_address", "addr", "bind-address"}

is_network_related_name(name) {
    n := network_related_names[_]
    regex.match(sprintf("(?i).*%s.*", [n]), name)
}

is_suspicious_network_value(value) {
    value.ir_type == "String"
    val := suspicious_network_values[_]
    value.value == val
}

get_key_string(key) = result {
    key.ir_type == "String"
    result := key.value
} else = result {
    key.ir_type == "VariableReference"
    result := key.value
} else = result {
    result := ""
}

collect_access_nodes(access) = result {
    result := [node | walk(access, [_, node]); node.ir_type == "Access"]
}

unsafe_network_binding_results[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, hash_val])
    hash_val.ir_type == "Hash"
    
    pair := hash_val.value[_]
    
    key_str := get_key_string(pair.key)
    is_network_related_name(key_str)
    
    pair.value.ir_type == "String"
    val := suspicious_network_values[_]
    pair.value.value == val
    
    result := {
        "type": "sec_invalid_bind",
        "element": pair.value,
        "path": parent.path,
        "description": "Improper Access Control - Network binding configured to listen on all interfaces (0.0.0.0). (CWE-284)"
    }
}

unsafe_network_binding_results[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, var])
    var.ir_type == "Variable"
    
    is_network_related_name(var.name)
    is_suspicious_network_value(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var.value,
        "path": parent.path,
        "description": "Improper Access Control - Network binding configured to listen on all interfaces (0.0.0.0). (CWE-284)"
    }
}

unsafe_network_binding_results[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, a])
    a.ir_type == "Assign"
    
    a.left.ir_type == "Access"
    
    chain := collect_access_nodes(a.left)
    access_node := chain[_]
    key_str := get_key_string(access_node.right)
    is_network_related_name(key_str)
    is_suspicious_network_value(a.right)
    
    result := {
        "type": "sec_invalid_bind",
        "element": a.right,
        "path": parent.path,
        "description": "Improper Access Control - Network binding configured to listen on all interfaces (0.0.0.0). (CWE-284)"
    }
}

unsafe_network_binding_results[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, access])
    access.ir_type == "Access"
    
    left_node := access.left
    left_node.ir_type == "Access"
    
    chain := collect_access_nodes(access)
    node := chain[_]
    key_str := get_key_string(node.right)
    is_network_related_name(key_str)
    
    walk(parent, [_, a])
    a.ir_type == "Assign"
    a.left == access
    is_suspicious_network_value(a.right)
    
    result := {
        "type": "sec_invalid_bind",
        "element": a.right,
        "path": parent.path,
        "description": "Improper Access Control - Network binding configured to listen on all interfaces (0.0.0.0). (CWE-284)"
    }
}

unsafe_network_binding_results[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_network_related_name(attr.name)
    is_suspicious_network_value(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Network binding configured to listen on all interfaces (0.0.0.0). (CWE-284)"
    }
}

unsafe_network_binding_results[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, a])
    a.ir_type == "Assign"
    
    a.right.ir_type == "Hash"
    pair := a.right.value[_]
    
    key_str := get_key_string(pair.key)
    is_network_related_name(key_str)
    
    pair.value.ir_type == "String"
    val := suspicious_network_values[_]
    pair.value.value == val
    
    result := {
        "type": "sec_invalid_bind",
        "element": pair.value,
        "path": parent.path,
        "description": "Improper Access Control - Network binding configured to listen on all interfaces (0.0.0.0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    result := unsafe_network_binding_results[_]
}