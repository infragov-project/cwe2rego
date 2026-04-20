package glitch

import data.glitch_lib

binding_patterns := {"bind", "listen", "host", "ip", "addr", "interface", "server"}
unrestricted_ips := {"0.0.0.0", "::"}

is_binding_keyword(name) {
    lower_name := lower(name)
    pattern := binding_patterns[_]
    contains(lower_name, pattern)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var_node := vars[_]
    is_binding_keyword(var_node.name)
    var_value := glitch_lib.get_string_value(var_node.value)
    var_value != ""
    unrestricted_ips[var_value]
    result := {
        "type": "sec_invalid_bind",
        "element": var_node,
        "path": parent.path,
        "description": sprintf("Variable '%s' binds to unrestricted IP address %s (CWE-1327)", [var_node.name, var_value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_binding_keyword(attr.name)
    attr_value := glitch_lib.get_string_value(attr.value)
    attr_value != ""
    unrestricted_ips[attr_value]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Attribute '%s' binds to unrestricted IP address %s (CWE-1327)", [attr.name, attr_value])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var_node := vars[_]
    walk(var_node.value, [path, node])
    node.ir_type == "String"
    unrestricted_ips[node.value]
    path_str := concat(".", path)
    is_binding_keyword(path_str)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": sprintf("Unrestricted bind address in hash structure (path: %s) (CWE-1327)", [path_str])
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
    node.ir_type == "String"
    unrestricted_ips[node.value]
    path_str := concat(".", path)
    is_binding_keyword(path_str)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": sprintf("Unrestricted bind address in hash structure (path: %s) (CWE-1327)", [path_str])
    }
}