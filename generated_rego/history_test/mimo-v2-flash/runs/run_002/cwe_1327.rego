package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check for bind address attributes in variable values
    bind_keywords := {"bind_address", "listen_address", "host", "ip_address", "interface", "server_bind", "endpoint", "ip", "bind-address", "addr"}
    var.name_lower := lower(var.name)
    contains_bind_keyword := any([contains(var.name_lower, kw) | kw := bind_keywords[_]])
    
    # Check if the value is 0.0.0.0 or *
    var.value.ir_type == "String"
    (var.value.value == "0.0.0.0" | var.value.value == "*")
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Service binds to unrestricted IP address (0.0.0.0 or *) - This may expose the service to all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for bind address attributes in atomic unit attributes
    bind_keywords := {"bind_address", "listen_address", "host", "ip_address", "interface", "server_bind", "endpoint", "ip", "bind-address", "addr"}
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr_name_lower := lower(attr.name)
    contains_bind_keyword := any([contains(attr_name_lower, kw) | kw := bind_keywords[_]])
    
    # Check if the value is 0.0.0.0 or *
    attr.value.ir_type == "String"
    (attr.value.value == "0.0.0.0" | attr.value.value == "*")
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Service binds to unrestricted IP address (0.0.0.0 or *) - This may expose the service to all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for nested hash values with bind address
    bind_keywords := {"bind_address", "listen_address", "host", "ip_address", "interface", "server_bind", "endpoint", "ip", "bind-address", "addr"}
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Look for hash values that might contain bind address settings
    attr.value.ir_type == "Hash"
    walk(attr.value, [path, n])
    n.ir_type == "String"
    (n.value == "0.0.0.0" | n.value == "*")
    
    # Check if the path includes a bind keyword
    path_str := concat(".", path)
    path_lower := lower(path_str)
    contains_bind_keyword := any([contains(path_lower, kw) | kw := bind_keywords[_]])
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Service binds to unrestricted IP address (0.0.0.0 or *) - This may expose the service to all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check for nested hash values with bind address in variables
    bind_keywords := {"bind_address", "listen_address", "host", "ip_address", "interface", "server_bind", "endpoint", "ip", "bind-address", "addr"}
    
    # Look for hash values that might contain bind address settings
    var.value.ir_type == "Hash"
    walk(var.value, [path, n])
    n.ir_type == "String"
    (n.value == "0.0.0.0" | n.value == "*")
    
    # Check if the path includes a bind keyword
    path_str := concat(".", path)
    path_lower := lower(path_str)
    contains_bind_keyword := any([contains(path_lower, kw) | kw := bind_keywords[_]])
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Service binds to unrestricted IP address (0.0.0.0 or *) - This may expose the service to all network interfaces. (CWE-1327)"
    }
}