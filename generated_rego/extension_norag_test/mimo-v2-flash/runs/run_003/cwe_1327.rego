package glitch

import data.glitch_lib

allowed_attributes = {
    "bind_address", "listen_address", "host", "ip_address",
    "server_address", "service_address", "network_interface", "private_ip"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name in allowed_attributes
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - This may allow unrestricted network access. (CWE-1327)"
    }
}