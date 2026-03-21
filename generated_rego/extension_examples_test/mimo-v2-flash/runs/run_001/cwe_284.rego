package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_vars := glitch_lib.all_variables(parent)
    var := all_vars[_]
    var.name == "mysql_bind_address" or var.name == "bind_address" or var.name == "bind_ip" or var.name == "ip" or var.name == "address" or var.name == "server_addr" or var.name == "server_address"
    var.value.ir_type == "String"
    var.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Service bound to all network interfaces (0.0.0.0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    attr.name == "mysql_bind_address" or attr.name == "bind_address" or attr.name == "bind_ip" or attr.name == "ip" or attr.name == "address" or attr.name == "server_addr" or attr.name == "server_address"
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Service bound to all network interfaces (0.0.0.0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_vars := glitch_lib.all_variables(parent)
    var := all_vars[_]
    var.value.ir_type == "Hash"
    walk(var.value, [path, node])
    node.ir_type == "String"
    node.value == "0.0.0.0"
    count(path) > 0
    path[count(path) - 1] == "value"
    key_path := array.slice(path, 0, count(path) - 1)
    walk(var.value, [key_path, key_node])
    key_node.ir_type == "VariableReference"
    regex.match("ip|address|bind|server", key_node.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Service bound to all network interfaces (0.0.0.0) in configuration hash. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    attr.value.ir_type == "Hash"
    walk(attr.value, [path, node])
    node.ir_type == "String"
    node.value == "0.0.0.0"
    count(path) > 0
    path[count(path) - 1] == "value"
    key_path := array.slice(path, 0, count(path) - 1)
    walk(attr.value, [key_path, key_node])
    key_node.ir_type == "VariableReference"
    regex.match("ip|address|bind|server", key_node.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Service bound to all network interfaces (0.0.0.0) in configuration hash. (CWE-284)"
    }
}