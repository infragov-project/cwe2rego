package glitch

import data.glitch_lib

wildcard_values := {"0.0.0.0", "::", "0:0:0:0:0:0:0:0", "*", ""}

is_wildcard_value(val) {
    val.ir_type == "String"
    wildcard_values[val.value]
}

binding_names := {
    "listen_address", "listenaddr", "listen_addr", "listen_on", "listening_address",
    "bind_address", "bind_addr", "bindaddress", "bind", "bind_host", "bind_ip",
    "bind_interface", "host", "hostname", "address", "ip_address", "ipaddress",
    "ip", "network_address", "interface", "network_interface", "advertise_address",
    "connect_address", "accept_address", "server_address", "listen",
    "db_host", "database_host", "db_address", "cluster_address", "peer_address",
    "replication_address", "admin_address", "management_address", "api_host",
    "api_address", "addr"
}

normalize_name(name) = n {
    startswith(name, ":")
    n = lower(substring(name, 1, -1))
} else = n {
    n = lower(name)
}

is_binding_name(name) {
    norm := normalize_name(name)
    binding_names[norm]
}

is_binding_name(name) {
    norm := normalize_name(name)
    contains(norm, "bind")
}

is_binding_name(name) {
    norm := normalize_name(name)
    contains(norm, "listen")
}

is_binding_name(name) {
    norm := normalize_name(name)
    contains(norm, "addr")
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
        "description": "Binding to an unrestricted IP address - A service is configured to accept connections on all available network interfaces using a wildcard address. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_binding_name(v.name)
    is_wildcard_value(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - A service is configured to accept connections on all available network interfaces using a wildcard address. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    {"String", "VariableReference"}[entry.key.ir_type]
    is_binding_name(entry.key.value)
    is_wildcard_value(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - A service is configured to accept connections on all available network interfaces using a wildcard address. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"allow_all", "open_access", "public_access", "publicly_accessible"}[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service is configured with unrestricted or public network access explicitly enabled. (CWE-1327)"
    }
}