package glitch

import data.glitch_lib

# Unrestricted IP values
unrestricted_ip_values := {"0.0.0.0", "::", "::0", "0000:0000:0000:0000:0000:0000:0000:0000", "*", "all", "any", "0.0.0.0/0", "::/0", ""}

# Binding-related attribute names
binding_attributes := {
    "bind_address", "listen_address", "host", "address", "interface", "socket_bind",
    "bind_ip", "listen_ip", "host_ip", "client_bind", "cluster_bind",
    "public_ip_enabled", "assign_public_ip", "publicly_accessible", "source_ranges", "allowed_hosts",
    "container_port_host_ip", "host_binding", "publish_ports", "external_ip",
    "frontend_ip", "backend_binding", "ingress_ip", "origin_binding",
    "memcached_bind", "redis_bind", "kafka_listeners", "broker_bind",
    "bind", "listen", "source_range", "cidr", "allow"
}

# Check if primitive value is unrestricted IP
is_unrestricted_ip(value) {
    value.ir_type == "String"
    unrestricted_ip_values[value.value]
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

# Check if attribute name indicates binding context
is_binding_attribute(name) {
    lower_name := lower(name)
    binding := binding_attributes[_]
    lower_name == binding
} else {
    lower_name := lower(name)
    contains(lower_name, "bind")
} else {
    lower_name := lower(name)
    contains(lower_name, "listen")
} else {
    lower_name := lower(name)
    contains(lower_name, "host")
} else {
    lower_name := lower(name)
    contains(lower_name, "address")
} else {
    lower_name := lower(name)
    regex.match(".*ip.*", lower_name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_binding_attribute(attr.name)
    is_unrestricted_ip(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service binds to all interfaces making it accessible from any network. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_binding_attribute(attr.name)
    attr.value.ir_type == "Array"
    [_, elem] := walk(attr.value.value)

    # Check if element is a primitive with unrestricted IP
    elem.ir_type == "String"
    unrestricted_ip_values[elem.value]

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service binds to all interfaces making it accessible from any network. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_binding_attribute(attr.name)
    attr.value.ir_type == "Hash"
    [_, val] := walk(attr.value.value)

    # Check if value is a primitive (String, Null, Undef) with unrestricted IP
    val.ir_type == "String"
    unrestricted_ip_values[val.value]

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service binds to all interfaces making it accessible from any network. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_binding_attribute(attr.name)
    attr.value.ir_type == "Hash"
    [_, val] := walk(attr.value.value)

    val.ir_type == "Null"

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service binds to all interfaces making it accessible from any network. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_binding_attribute(attr.name)
    attr.value.ir_type == "Hash"
    [_, val] := walk(attr.value.value)

    val.ir_type == "Undef"

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service binds to all interfaces making it accessible from any network. (CWE-1327)"
    }
}