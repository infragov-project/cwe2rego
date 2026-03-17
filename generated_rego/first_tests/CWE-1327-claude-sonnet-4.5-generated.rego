package glitch

import data.glitch_lib

binding_attributes := {
    "bind_address", "bind", "binding", "binds",
    "listen_address", "listen", "listenaddr", "listener",
    "host", "hostname", "host_address",
    "address", "addr", "ip_address", "ip",
    "server_address", "server_host",
    "endpoint", "endpoint_address",
    "network_interface", "interface",
    "public_ip", "external_ip",
    "allowed_hosts", "allowed_ips",
    "source_address", "source_ranges"
}

public_access_attributes := {
    "publicly_accessible", "public_access", "public",
    "expose_publicly", "exposed_to", "exposure"
}

is_unrestricted_ip(value) {
    value.ir_type == "String"
    value.value == "0.0.0.0"
}

is_unrestricted_ip(value) {
    value.ir_type == "String"
    value.value == "::"
}

is_unrestricted_ip(value) {
    value.ir_type == "String"
    value.value == "::0"
}

is_unrestricted_ip(value) {
    value.ir_type == "String"
    value.value == "*"
}

is_unrestricted_ip(value) {
    value.ir_type == "String"
    lower(value.value) == "all"
}

is_unrestricted_ip(value) {
    value.ir_type == "String"
    lower(value.value) == "any"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    lower_name := lower(attr.name)
    lower_name == binding_attributes[_]

    is_unrestricted_ip(attr.value)

    result := {
        "type": "sec_unrestricted_ip_binding",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service is configured to bind to an unrestricted IP address (0.0.0.0, ::, or *), which exposes it to all network interfaces. This may allow unauthorized access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]

    lower_name := lower(var.name)
    lower_name == binding_attributes[_]

    is_unrestricted_ip(var.value)

    result := {
        "type": "sec_unrestricted_ip_binding",
        "element": var,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Variable is configured with an unrestricted IP address (0.0.0.0, ::, or *), which may be used to bind services to all network interfaces. This may allow unauthorized access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    lower_name := lower(attr.name)
    lower_name == public_access_attributes[_]

    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_unrestricted_ip_binding",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service is configured as publicly accessible, which may expose it to all network interfaces and allow unauthorized access. (CWE-1327)"
    }
}