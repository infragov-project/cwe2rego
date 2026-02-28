package glitch

import data.glitch_lib

is_wildcard_ip_string(v) {
    regex.match(`^0\.0\.0\.0(/0)?$`, v)
}

is_wildcard_ip_string(v) {
    v == "::"
}

is_wildcard_ip_string(v) {
    v == "0:0:0:0:0:0:0:0"
}

is_wildcard_ip_string(v) {
    v == "*"
}

is_wildcard_ip(expr) {
    expr.ir_type == "String"
    is_wildcard_ip_string(expr.value)
}

is_binding_attr_name(name) {
    keywords := ["listen", "bind", "host", "address", "addr", "endpoint", "source", "socket", "interface"]
    keyword := keywords[_]
    regex.match(sprintf("(?i).*%s.*", [keyword]), name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_binding_attr_name(attr.name)
    is_wildcard_ip(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - A network-binding attribute is assigned a wildcard IP, exposing the service on all interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    pair.key.ir_type == "String"
    is_binding_attr_name(pair.key.value)
    is_wildcard_ip(pair.value)
    result := {
        "type": "sec_invalid_bind",
        "element": pair.value,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - A network-binding attribute is assigned a wildcard IP, exposing the service on all interfaces. (CWE-1327)"
    }
}