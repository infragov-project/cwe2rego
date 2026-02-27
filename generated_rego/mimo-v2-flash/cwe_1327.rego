package glitch

import data.glitch_lib

binding_pattern := "(?i)(bind_address|bindaddr|listen_address|listenaddr|address|ip_address|host|interface|endpoint|server_address|vncserver_listen|bind_addr|bindaddress|source)"

check_ip(value) {
    value.ir_type == "String"
    regex.match("^0\\.0\\.0\\.0", value.value)
} else {
    value.ir_type == "String"
    regex.match("^0\\.0\\.0\\.0/0", value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    regex.match(binding_pattern, node.name)
    check_ip(node.value)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - The service is bound to 0.0.0.0, which may expose it to unrestricted access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    pair.key.ir_type == "String"
    regex.match(binding_pattern, pair.key.value)
    check_ip(pair.value)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - The service is bound to 0.0.0.0, which may expose it to unrestricted access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "Hash"
    hash := node.value
    pair := hash.value[_]
    pair.key.ir_type == "String"
    regex.match(binding_pattern, pair.key.value)
    check_ip(pair.value)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - The service is bound to 0.0.0.0, which may expose it to unrestricted access. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match(binding_pattern, attr.name)
    check_ip(attr.value)
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address - The service is bound to 0.0.0.0, which may expose it to unrestricted access. (CWE-1327)"
    }
}