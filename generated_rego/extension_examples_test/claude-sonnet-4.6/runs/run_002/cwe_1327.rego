package glitch

import data.glitch_lib

wildcard_ip_pattern := `^(0\.0\.0\.0|::|0\.0\.0\.0/0|::/0|\*|any)$`

bind_field_pattern := `(?i)(^|[^a-z0-9])(listen_address|listen_on|listen|bind_address|bind_addr|bindaddress|bind_ip|bindip|bind|ip_address|ip_addr|addr|address|hostname|host|network_address|server_address|interface|iface|ip)([^a-z0-9]|$)`

is_wildcard_ip(val) {
    val.ir_type == "String"
    regex.match(wildcard_ip_pattern, val.value)
}

is_bind_field(name) {
    regex.match(bind_field_pattern, name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_bind_field(v.name)
    is_wildcard_ip(v.value)
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Variable binds to a wildcard address. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_bind_field(attr.name)
    is_wildcard_ip(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Attribute binds to a wildcard address. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    is_bind_field(entry.key.value)
    is_wildcard_ip(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Hash entry with string key binds to a wildcard address. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "VariableReference"
    is_bind_field(entry.key.value)
    is_wildcard_ip(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Hash entry with variable reference key binds to a wildcard address. (CWE-1327)"
    }
}