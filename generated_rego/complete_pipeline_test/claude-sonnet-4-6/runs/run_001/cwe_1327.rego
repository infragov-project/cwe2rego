package glitch

import data.glitch_lib

wildcard_ips := {"0.0.0.0", "::", "*"}

binding_keywords := {"bind", "listen", "address", "addr", "host", "ip", "endpoint", "socket", "interface"}

is_wildcard_ip(value) {
    value.ir_type == "String"
    value.value == wildcard_ips[_]
}

name_has_binding_keyword(name) {
    keyword := binding_keywords[_]
    glitch_lib.contains(name, keyword)
}

get_key_name(key) = v {
    key.ir_type == "String"
    v := key.value
} else = v {
    key.ir_type == "VariableReference"
    v := key.value
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    name_has_binding_keyword(v.name)
    is_wildcard_ip(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service is bound to a wildcard address, exposing it on all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    name_has_binding_keyword(attr.name)
    is_wildcard_ip(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service is bound to a wildcard address, exposing it on all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    key_name := get_key_name(entry.key)
    name_has_binding_keyword(key_name)
    is_wildcard_ip(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - Service is bound to a wildcard address, exposing it on all network interfaces. (CWE-1327)"
    }
}