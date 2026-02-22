package glitch

import data.glitch_lib

is_bad_ip(value) {
    value.ir_type == "String"
    value.value == "0.0.0.0"
}

is_bad_port_string(s) {
    parts := split(s, ":")
    count(parts) == 1
} else {
    parts := split(s, ":")
    count(parts) == 2
} else {
    parts := split(s, ":")
    count(parts) == 3
    parts[0] == "0.0.0.0"
}

is_bad_port_value(value) {
    value.ir_type == "String"
    is_bad_port_string(value.value)
} else {
    value.ir_type == "Array"
    some element in value.value
    element.ir_type == "String"
    is_bad_port_string(element.value)
}

is_bad_cloud_boolean(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_bad_cloud_cidr(value) {
    value.ir_type == "String"
    value.value == "0.0.0.0/0"
} else {
    value.ir_type == "Array"
    some element in value.value
    element.ir_type == "String"
    element.value == "0.0.0.0/0"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    ip_attrs = {"listen_address", "bind_address", "host", "ip_address", "listenaddr", "server_address", "hostip"}
    lower_name = lower(attr.name)
    ip_attrs_set := ip_attrs
    lower_name == ip_attrs_set[_]
    is_bad_ip(attr.value)
    result := {
        "type": "binding_unrestricted_ip",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service binds to 0.0.0.0, which is unrestricted and accessible from all interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    port_attrs = {"ports", "containerport", "hostport", "published_ports", "expose"}
    lower_name = lower(attr.name)
    port_attrs_set := port_attrs
    lower_name == port_attrs_set[_]
    is_bad_port_value(attr.value)
    result := {
        "type": "binding_unrestricted_ip",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service binds to 0.0.0.0, which is unrestricted and accessible from all interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    cloud_boolean_attr = {"publicly_accessible"}
    lower_name = lower(attr.name)
    cloud_boolean_set := cloud_boolean_attr
    lower_name == cloud_boolean_set[_]
    is_bad_cloud_boolean(attr.value)
    result := {
        "type": "binding_unrestricted_ip",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service binds to 0.0.0.0, which is unrestricted and accessible from all interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    cloud_cidr_attr = {"ingress_cidr", "allowed_public_ips"}
    lower_name = lower(attr.name)
    cloud_cidr_set := cloud_cidr_attr
    lower_name == cloud_cidr_set[_]
    is_bad_cloud_cidr(attr.value)
    result := {
        "type": "binding_unrestricted_ip",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service binds to 0.0.0.0, which is unrestricted and accessible from all interfaces. (CWE-1327)"
    }
}