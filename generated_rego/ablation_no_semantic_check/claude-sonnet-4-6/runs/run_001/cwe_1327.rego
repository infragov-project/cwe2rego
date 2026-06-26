package glitch

import data.glitch_lib

bind_address_attrs := {"listen_address", "listenaddr", "listen_on", "bind_address", "bind_addr", "host", "hostname", "address", "ip_address", "listen", "bind", "endpoint", "server_address", "advertise_addr", "client_addr", "rpc_addr", "grpc_address", "http_addr"}

cidr_attrs := {"cidr", "cidr_block", "allowed_cidr", "ingress_cidr", "egress_cidr", "source_ranges", "source_address_prefix", "allowed_ip_ranges", "source", "remote_ip_prefix"}

public_access_attrs := {"publicly_accessible", "public_access", "public_ip_enabled", "associate_public_ip_address", "public_network_access_enabled", "internet_facing", "enable_public_endpoint"}

wildcard_bind_values := {"0.0.0.0", "::", "*"}

wildcard_cidr_values := {"0.0.0.0/0", "::/0", "*"}

public_enabled_strings := {"yes", "enabled", "public", "internet-facing", "true"}

is_wildcard_bind(value) {
    value.ir_type == "String"
    value.value == wildcard_bind_values[_]
}

is_wildcard_cidr(value) {
    value.ir_type == "String"
    value.value == wildcard_cidr_values[_]
}

is_wildcard_cidr(value) {
    value.ir_type == "Array"
    item := value.value[_]
    item.ir_type == "String"
    item.value == wildcard_cidr_values[_]
}

is_public_enabled(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_public_enabled(value) {
    value.ir_type == "String"
    lower(value.value) == public_enabled_strings[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == bind_address_attrs[_]
    is_wildcard_bind(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service is bound to a wildcard address accepting connections from all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == cidr_attrs[_]
    is_wildcard_cidr(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Network configuration permits traffic from all IP addresses via wildcard CIDR. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == public_access_attrs[_]
    is_public_enabled(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Resource is publicly accessible without IP restriction. (CWE-1327)"
    }
}