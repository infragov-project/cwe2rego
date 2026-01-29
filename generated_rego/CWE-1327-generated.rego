package glitch

import data.glitch_lib

unrestricted_ips := {"0.0.0.0", "0.0.0.0/0", "::", "::/0", "*", "any", ""}

ip_binding_attributes := {
    "listen_address", "listenaddr", "listen_addr", "listener_address",
    "bind_address", "bind_addr", "bindaddr", "binding_address",
    "host", "hostname", "host_address", "server_host",
    "address", "addr", "ip_address", "ip_addr",
    "endpoint", "endpoint_address", "service_endpoint",
    "source_address", "source_ranges", "source_cidr",
    "allowed_ips", "allowed_ip_ranges", "allowed_sources",
    "cidr_blocks", "cidr", "cidr_range", "ip_ranges",
    "whitelist", "allowlist", "permitted_ips",
    "ingress", "inbound_rules"
}

is_unrestricted_ip(value) {
    value.ir_type == "String"
    unrestricted_ips[value.value]
}

is_unrestricted_ip(value) {
    value.ir_type == "Array"
    item := value.value[_]
    item.ir_type == "String"
    unrestricted_ips[item.value]
}

is_unrestricted_ip(value) {
    value.ir_type == "Hash"
    dict_value := value.value[_]
    is_unrestricted_ip(dict_value)
}

is_unrestricted_ip(value) {
    value.ir_type == "Null"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    lower(attr.name) == ip_binding_attributes[_]
    is_unrestricted_ip(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service is configured to bind to an unrestricted IP address (0.0.0.0 or ::), which may expose it to unauthorized access. (CWE-1327)"
    }
}