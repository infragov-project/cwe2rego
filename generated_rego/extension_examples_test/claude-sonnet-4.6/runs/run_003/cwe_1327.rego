package glitch

import data.glitch_lib

wildcard_values := {"0.0.0.0", "::", "*"}

is_wildcard_string(v) {
    v.ir_type == "String"
    v.value == wildcard_values[_]
}

is_binding_name(name) {
    regex.match(`(?i)(bind|listen)`, name)
}

is_binding_name(name) {
    regex.match(`(?i)(^|[^a-zA-Z0-9])(addr|address|ip_address)([^a-zA-Z0-9]|$)`, name)
}

is_binding_name(name) {
    regex.match(`(?i)^(ip|host|interface|iface|endpoint|socket)$`, name)
}

is_binding_key_name(name) {
    is_binding_name(name)
}

is_binding_key_name(name) {
    startswith(name, ":")
    rest := substring(name, 1, count(name) - 1)
    is_binding_name(rest)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_binding_name(attr.name)
    is_wildcard_string(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service is bound to a wildcard IP address, exposing all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_binding_name(v.name)
    is_wildcard_string(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service is bound to a wildcard IP address, exposing all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, entry])
    entry.key.ir_type
    is_binding_key_name(entry.key.value)
    is_wildcard_string(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service is bound to a wildcard IP address, exposing all network interfaces. (CWE-1327)"
    }
}