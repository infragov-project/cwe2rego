package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for bind/listen address attributes (case-insensitive)
    regex.match("(?i)^(bind_address|listen_address|host|ip|address|server_ip|service_address|listening_interface|host_ip)$", attr.name)

    # Check for explicit 0.0.0.0 binding in string values
    attr.value.ir_type == "String"
    regex.match("^0\\.0\\.0\\.0(:.*)?$", attr.value.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Avoid binding to 0.0.0.0. (CWE-1327)"
    }
}