package glitch

import data.glitch_lib

risky_binding_keywords := {
    "bind", "listen", "addr", "address", "ip", "host", "hostname",
    "interface", "bind_address", "listen_address", "bind_ip", "bind_host",
    "listen_host", "listen_ip", "advertise_addr", "client_addr"
}

risky_binding_values := {"0.0.0.0", "::", "::0", "*"}

is_risky_name(name) {
    keyword := risky_binding_keywords[_]
    glitch_lib.contains(name, keyword)
}

is_unrestricted_value(value) {
    value.ir_type == "String"
    risky_binding_values[value.value]
}

is_unrestricted_value(value) {
    value.ir_type == "Null"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    v := vars[_]

    is_risky_name(v.name)
    is_unrestricted_value(v.value)

    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Unrestricted Network Service Binding - A variable is configured with a wildcard or all-interface binding address, potentially exposing services beyond their intended network boundary. (CWE-605)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    is_risky_name(attr.name)
    is_unrestricted_value(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted Network Service Binding - A service attribute is configured to bind on all network interfaces using a wildcard or unspecified address. (CWE-605)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"

    entry := hash_node.value[_]
    is_risky_name(entry.key.value)
    is_unrestricted_value(entry.value)

    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Unrestricted Network Service Binding - A hash configuration entry is set to a wildcard or all-interface binding address, potentially exposing services beyond their intended network boundary. (CWE-605)"
    }
}