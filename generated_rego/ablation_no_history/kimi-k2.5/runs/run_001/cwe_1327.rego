package glitch

import data.glitch_lib

unrestricted_patterns := {
    "0.0.0.0",
    "::",
    "[::]",
    "0.0.0.0/0",
    "::/0",
    "inaddr_any",
    "*",
    "all",
    "any"
}

is_unrestricted_address(str) {
    lower_str := lower(str)
    unrestricted_patterns[lower_str]
} else {
    lower_str := lower(str)
    regex.match("^\\*+$", lower_str)
}

is_bind_keyword(name) {
    lower_name := lower(name)
    bind_keywords := {
        "bind",
        "listening",
        "listen",
        "listenaddr",
        "listen_address",
        "bind_addr",
        "bind_address",
        "host",
        "addr",
        "address",
        "ip",
        "ip_address",
        "ipv4",
        "ipv6",
        "socket",
        "interface",
        "iface"
    }
    glitch_lib.contains(lower_name, bind_keywords[_])
    not glitch_lib.contains(lower_name, "hostname")
    not glitch_lib.contains(lower_name, "domain")
    not glitch_lib.contains(lower_name, "hosts")
}

find_unrestricted_in_value(node) {
    node.ir_type == "String"
    is_unrestricted_address(node.value)
} else {
    node.ir_type == "VariableReference"
    is_unrestricted_address(node.value)
} else {
    walk(node, [_, child])
    child.ir_type == "String"
    is_unrestricted_address(child.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    node := vars[_]

    is_bind_keyword(node.name)
    find_unrestricted_in_value(node.value)

    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0, ::, or other wildcard addresses as this exposes them on all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    var.value.ir_type == "Hash"
    some _, entry
    var.value.value[_] = entry
    
    is_bind_keyword(entry.key.value)
    find_unrestricted_in_value(entry.value)

    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0, ::, or other wildcard addresses as this exposes them on all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_bind_keyword(attr.name)
    find_unrestricted_in_value(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0, ::, or other wildcard addresses as this exposes them on all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.value.ir_type == "Hash"
    some _, entry
    attr.value.value[_] = entry
    
    is_bind_keyword(entry.key.value)
    find_unrestricted_in_value(entry.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0, ::, or other wildcard addresses as this exposes them on all network interfaces. (CWE-1327)"
    }
}