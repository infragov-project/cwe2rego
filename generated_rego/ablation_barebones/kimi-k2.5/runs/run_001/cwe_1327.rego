package glitch

import data.glitch_lib

ip_binding_attrs := {"listenaddr", "listen", "bind", "host", "address", "ip", "bindaddr", "bind_address", "listen_address", "host_ip", "source_ip", "listen_addr", "bind_addr"}

unrestricted_ips := {"0.0.0.0", "::", "0.0.0.0/0", "::/0", "0.0.0.0/32", "::/128", "[::]", "[::]/0"}

lower_trim(s) = lower(trim_space(trim(s, `"`)))

is_unrestricted_string(value) {
    value.ir_type == "String"
    lower_val := lower_trim(value.value)
    unrestricted_ips[lower_val]
}

is_unrestricted_regex(value) {
    value.ir_type == "String"
    lower_val := lower_trim(value.value)
    regex.match(`.*\b0\.0\.0\.0\b.*`, lower_val)
}

is_unrestricted_regex(value) {
    value.ir_type == "String"
    lower_val := lower_trim(value.value)
    regex.match(`.*\[?::\]?.*`, lower_val)
}

is_unrestricted_ip(value) {
    is_unrestricted_string(value)
} else {
    is_unrestricted_regex(value)
}

array_contains_unrestricted_ip(arr) {
    some elem
    elem = arr.value[_]
    elem.ir_type == "String"
    is_unrestricted_ip(elem)
}

hash_contains_unrestricted_ip(h) {
    some key
    val = h.value[key]
    val.ir_type == "String"
    is_unrestricted_ip(val)
}

hash_contains_unrestricted_ip(h) {
    some key
    val = h.value[key]
    val.ir_type == "Array"
    array_contains_unrestricted_ip(val)
}

has_unrestricted_ip(value) {
    value.ir_type == "String"
    is_unrestricted_ip(value)
} else {
    value.ir_type == "Array"
    array_contains_unrestricted_ip(value)
} else {
    value.ir_type == "Hash"
    hash_contains_unrestricted_ip(value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    ip_binding_attrs[lower(attr.name)]
    has_unrestricted_ip(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Avoid binding services to 0.0.0.0 or :: as it exposes them to all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    ip_binding_attrs[lower(var.name)]
    has_unrestricted_ip(var.value)

    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Avoid binding services to 0.0.0.0 or :: as it exposes them to all network interfaces. (CWE-1327)"
    }
}