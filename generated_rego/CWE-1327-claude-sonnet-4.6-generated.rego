package glitch

import data.glitch_lib

binding_attr_names := {
    "listen_address", "listenaddr", "listen",
    "bind_address", "bind", "bind_ip", "bind-address", "bind_addr",
    "host", "hostname",
    "address", "ip_address", "ip",
    "interface", "endpoint",
    "advertise_addr", "client_addr",
    "grpc_listen_addr", "http_listen_addr",
    "source", "src",
    "cidr", "cidr_block", "cidr_blocks", "ipv6_cidr_blocks",
    "source_ranges", "source_address_prefix",
    "allowed_cidr_blocks", "cluster_ipv4_cidr",
    "load_balancer_source_ranges", "authorized_networks"
}

wildcard_ip_pattern := "^(0\\.0\\.0\\.0|::|\\*)$"
wildcard_cidr_pattern := "^(0\\.0\\.0\\.0/0|::/0|\\*/\\*)$"

is_wildcard_ip(value) {
    value.ir_type == "String"
    regex.match(wildcard_ip_pattern, value.value)
}

is_wildcard_cidr(value) {
    value.ir_type == "String"
    regex.match(wildcard_cidr_pattern, value.value)
}

is_wildcard_value(value) {
    is_wildcard_ip(value)
}

is_wildcard_value(value) {
    is_wildcard_cidr(value)
}

is_wildcard_value(value) {
    value.ir_type == "Array"
    item := value.value[_]
    item.ir_type == "String"
    regex.match(wildcard_cidr_pattern, item.value)
}

is_binding_name(name) {
    binding_attr_names[lower(name)]
}

is_binding_name(name) {
    regex.match("(?i).*(bind|listen|addr|cidr|endpoint).*", name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_binding_name(attr.name)
    is_wildcard_value(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service configured to listen on all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    is_binding_name(entry.key.value)
    is_wildcard_value(entry.value)

    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service configured to listen on all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "publicly_accessible"
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Resource configured as publicly accessible without network restriction. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "associate_public_ip_address"
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Compute instance configured to associate a public IP address. (CWE-1327)"
    }
}