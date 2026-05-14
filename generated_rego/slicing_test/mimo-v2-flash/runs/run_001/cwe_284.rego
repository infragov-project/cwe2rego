package glitch

import data.glitch_lib

get_key_string(key) = str {
    key.ir_type == "String"
    str := key.value
} else {
    key.ir_type == "VariableReference"
    str := key.value
} else {
    key.ir_type == "Access"
    str := get_key_string(key.right)
} else {
    str := key.code
}

is_bind_address_key(key_str) {
    lower_key := lower(key_str)
    regex.match(".*(bind|ip|address|interface|net_bind|server_bind|addr|listen|port|bind_address|bind_addr|bind-address|mongodb_net_bindip).*", lower_key)
}

is_open_address(value) {
    value.ir_type == "String"
    (value.value == "0.0.0.0" or value.value == "::/0")
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    var.value.ir_type == "String"
    is_open_address(var.value)
    is_bind_address_key(var.name)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": sprintf("Insecure bind address: variable '%s' set to '%s'", [var.name, var.value.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    var.value.ir_type == "Hash"
    
    walk(var.value, [path, n])
    n.ir_type == "String"
    is_open_address(n)
    
    path_parts := [get_key_string(p) | p := path[_]; p.ir_type in ["String", "VariableReference", "Access"]]
    count(path_parts) > 0
    key_str := path_parts[count(path_parts) - 1]
    is_bind_address_key(key_str)
    
    result := {
        "type": "sec_invalid_bind",
        "element": n,
        "path": parent.path,
        "description": sprintf("Insecure bind address in hash variable '%s': key '%s' set to '%s'", [var.name, key_str, n.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    attr.value.ir_type == "String"
    is_open_address(attr.value)
    is_bind_address_key(attr.name)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Insecure bind address: attribute '%s' set to '%s'", [attr.name, attr.value.value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    attr.value.ir_type == "Hash"
    
    walk(attr.value, [path, n])
    n.ir_type == "String"
    is_open_address(n)
    
    path_parts := [get_key_string(p) | p := path[_]; p.ir_type in ["String", "VariableReference", "Access"]]
    count(path_parts) > 0
    key_str := path_parts[count(path_parts) - 1]
    is_bind_address_key(key_str)
    
    result := {
        "type": "sec_invalid_bind",
        "element": n,
        "path": parent.path,
        "description": sprintf("Insecure bind address in hash attribute '%s': key '%s' set to '%s'", [attr.name, key_str, n.value])
    }
}