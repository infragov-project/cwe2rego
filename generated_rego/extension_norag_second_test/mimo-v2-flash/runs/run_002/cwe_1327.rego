package glitch

import data.glitch_lib

binding_keywords := {
    "bind_address", "listen_address", "ip_address", "host", "server_bind",
    "public_ip", "private_ip", "endpoint", "network_interface", "service_address",
    "container_bind", "ip", "addr", "bind-address", "bind_ip", "address",
    "bindaddress", "bindaddr", "bind", "net_bindip"
}

check_unrestricted_ip(value) {
    value.ir_type == "String"
    value.value == "0.0.0.0"
}

check_unrestricted_ip(value) {
    value.ir_type == "Hash"
    pair := value.value[_]
    pair.key.ir_type == "String"
    pair.key.value == "0.0.0.0"
}

check_unrestricted_ip(value) {
    value.ir_type == "Hash"
    pair := value.value[_]
    pair.value.ir_type == "String"
    pair.value.value == "0.0.0.0"
}

check_unrestricted_ip(value) {
    value.ir_type == "Array"
    elem := value.value[_]
    elem.ir_type == "String"
    elem.value == "0.0.0.0"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower_name := lower(attr.name)
    binding_keywords[_] == lower_name
    check_unrestricted_ip(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Assignment of unrestricted IP address 0.0.0.0 to bind/listen attributes - Services should not bind to all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    lower_name := lower(var.name)
    binding_keywords[_] == lower_name
    check_unrestricted_ip(var.value)
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Assignment of unrestricted IP address 0.0.0.0 to bind/listen attributes - Services should not bind to all network interfaces. (CWE-1327)"
    }
}