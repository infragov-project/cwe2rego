package glitch

import data.glitch_lib

bind_field_pattern := "(?i)^(listen[_-]?addr(ess)?|bind[_-]?address|bind|listen|host|ip[_-]?address|server[_-]?address|network[_-]?interface|interface|iface|endpoint|socket|listen[_-]?on|advertise[_-]?addr|service[_-]?bind|rpc[_-]?bind|grpc[_-]?bind|api[_-]?listen|listening[_-]?address|accept[_-]?address)$"

is_wildcard_ip(value) {
    value.ir_type == "String"
    regex.match("^0\\.0\\.0\\.0(:\\d+)?$", value.value)
}

is_wildcard_ip(value) {
    value.ir_type == "String"
    value.value == "::"
}

is_wildcard_ip(value) {
    value.ir_type == "String"
    value.value == "0:0:0:0:0:0:0:0"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    regex.match(bind_field_pattern, attr.name)
    is_wildcard_ip(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to wildcard addresses (0.0.0.0 or ::). (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]

    regex.match(bind_field_pattern, v.name)
    is_wildcard_ip(v.value)

    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to wildcard addresses (0.0.0.0 or ::). (CWE-1327)"
    }
}