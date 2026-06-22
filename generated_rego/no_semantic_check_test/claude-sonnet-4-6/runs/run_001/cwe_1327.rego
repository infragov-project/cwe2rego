package glitch

import data.glitch_lib

binding_attr_names := {
    "listen_address", "listenaddr", "bind_address", "bind_ip", "bind_host",
    "host", "listen", "address", "interface", "ip_address", "listen_on",
    "server_address", "db_bind_address", "api_host", "server_host",
    "rpc_bind", "cluster_listen"
}

cidr_attr_names := {
    "cidr_blocks", "ingress_cidr", "allowed_ips", "source_ranges", "ip_whitelist"
}

wildcard_ips := {"0.0.0.0", "::", "*", "0:0:0:0:0:0:0:0"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == binding_attr_names[_]
    attr.value.ir_type == "String"
    attr.value.value == wildcard_ips[_]
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service is bound to a wildcard address exposing it to all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cidr_attr_names[_]
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0/0"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Unrestricted CIDR exposes service to all IP addresses. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cidr_attr_names[_]
    attr.value.ir_type == "Array"
    item := attr.value.value[_]
    item.ir_type == "String"
    item.value == "0.0.0.0/0"
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Unrestricted CIDR exposes service to all IP addresses. (CWE-1327)"
    }
}