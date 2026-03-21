package glitch

import data.glitch_lib

bind_keywords := {
    "bind", "listen", "address", "ip", "host", "server", "local", "interface",
    "bind_address", "listen_address", "ip_address", "server_address", "local_address",
    "bindip", "bind_ip", "bindaddr", "bind_addr", "listenaddr", "listen_addr", "host_address", "server_ip",
    "addr"
}

check_value(value_node) {
    value_node.ir_type == "String"
    regex.match("^0\\.0\\.0\\.0(?::\\d+)?$", value_node.value)
} else {
    value_node.ir_type == "String"
    value_node.value == "*"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    glitch_lib.contains(lower(variable.name), bind_keywords[_])
    check_value(variable.value)
    result := {
        "type": "sec_invalid_bind",
        "element": variable,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) in a variable - This can expose the service to all networks. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    glitch_lib.contains(lower(attr.name), bind_keywords[_])
    check_value(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) in an attribute - This can expose the service to all networks. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    key_element := entry.key
    key_str := get_key_string(key_element)
    glitch_lib.contains(lower(key_str), bind_keywords[_])
    value_element := entry.value
    check_value(value_element)
    result := {
        "type": "sec_invalid_bind",
        "element": value_element,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) in a configuration hash - This can expose the service to all networks. (CWE-1327)"
    }
}

get_key_string(key_node) = str {
    key_node.ir_type == "String"
    str := key_node.value
} else = str {
    key_node.ir_type == "VariableReference"
    str := key_node.value
} else = str {
    str := key_node.code
}