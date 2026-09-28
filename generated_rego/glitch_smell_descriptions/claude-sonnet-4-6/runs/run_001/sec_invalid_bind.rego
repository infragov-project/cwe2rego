package glitch

import data.glitch_lib

ip_keywords := ["ip", "addr", "address", "bind", "listen", "host", "cidr", "source", "destination", "inbound", "outbound", "interface", "network"]

is_unrestricted_ip(node) {
    node.ir_type == "String"
    regex.match("^0\\.0\\.0\\.0(/0)?$", node.value)
}

name_matches(name) {
    glitch_lib.contains(name, ip_keywords[_])
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    name_matches(v.name)
    is_unrestricted_ip(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Unrestricted IP Address - Binding to 0.0.0.0 or 0.0.0.0/0 exposes the resource to unrestricted network access. (CWE-668)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    name_matches(attr.name)
    is_unrestricted_ip(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted IP Address - Binding to 0.0.0.0 or 0.0.0.0/0 exposes the resource to unrestricted network access. (CWE-668)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    name_matches(entry.key.value)
    is_unrestricted_ip(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Unrestricted IP Address - Binding to 0.0.0.0 or 0.0.0.0/0 exposes the resource to unrestricted network access. (CWE-668)"
    }
}