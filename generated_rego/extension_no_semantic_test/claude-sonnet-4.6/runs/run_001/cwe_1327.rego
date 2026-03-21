package glitch

import data.glitch_lib

unrestricted_values := {"0.0.0.0", "::", "::0", "*", ""}

address_field_pattern := "(?i)^(listen_?addr(ess)?|bind_?addr(ess)?|listen|bind|address|host(name)?|ip(_address)?|listen_?ip|bind_?ip|server_address|server_host|network_address|host_address|interface|network_interface|listening_address|endpoint|socket_address|connect_address|incoming_address|advertised_address)$"

is_unrestricted_address(value) {
    value.ir_type == "String"
    value.value == unrestricted_values[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match(address_field_pattern, attr.name)
    is_unrestricted_address(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Service is bound to a wildcard address, exposing it on all available network interfaces. (CWE-1327)"
    }
}