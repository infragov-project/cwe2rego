package glitch

import data.glitch_lib

unrestricted_ip_values := {"0.0.0.0", "::", "::0", "[::]", "::0.0.0.0", "*"}

bind_keyword_pattern := "(?i)(bind|listen|host|address|addr|endpoint|socket|ip)"

match_bind_keyword(name) {
    cleaned := trim_prefix(name, ":")
    cleaned2 := trim_prefix(cleaned, "--")
    regex.match(bind_keyword_pattern, cleaned2)
}

check_unrestricted_ip(value) {
    value.ir_type == "String"
    v := lower(value.value)
    unrestricted_ip_values[v]
}

check_hash_key(key) {
    key.ir_type == "String"
    match_bind_keyword(key.value)
} else {
    key.ir_type == "VariableReference"
    match_bind_keyword(key.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, var])
    var.ir_type == "Variable"
    var.value.ir_type == "String"
    match_bind_keyword(var.name)
    check_unrestricted_ip(var.value)

    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0 or :: as this exposes them to all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    attr.value.ir_type == "String"
    match_bind_keyword(attr.name)
    check_unrestricted_ip(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0 or :: as this exposes them to all network interfaces. (CWE-1327)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    check_hash_key(entry.key)
    check_unrestricted_ip(entry.value)

    result := {
        "type": "sec_invalid_bind",
        "element": entry,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Services should not bind to 0.0.0.0 or :: as this exposes them to all network interfaces. (CWE-1327)"
    }
}