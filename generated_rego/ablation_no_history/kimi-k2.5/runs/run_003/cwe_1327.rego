package glitch

import data.glitch_lib

wildcard_ips := {"0.0.0.0", "0:0:0:0:0:0:0:0", "::", "0.0.0.0/0", "::/0", "INADDR_ANY", "*"}


bind_patterns := {"bind", "listen", "host", "addr", "address", "interface", "socket", "ip", "ingress", "endpoint", "listener"}


is_wildcard_string(value) {
    cleaned := lower(trim_space(replace(replace(value, "\"", ""), "'", "")))
    cleaned == wildcard_ips[_]
} else {
    cleaned := lower(trim_space(replace(replace(value, "\"", ""), "'", "")))
    regex.match("^0\\.0\\.0\\.0(/[0-9]+)?$", cleaned)
} else {
    cleaned := lower(trim_space(replace(replace(value, "\"", ""), "'", "")))
    regex.match("^::(/[0-9]+)?$", cleaned)
}


has_bind_context(name) {
    lower_name := lower(name)
    pattern := bind_patterns[_]
    regex.match(sprintf("(?i).*%s.*", [pattern]), lower_name)
}


find_wildcard_in_node(node) {
    node.ir_type == "String"
    is_wildcard_string(node.value)
} else {
    walk(node, [_, n])
    n.ir_type == "String"
    is_wildcard_string(n.value)
}


check_keyvalue(kv) {
    has_bind_context(kv.name)
    find_wildcard_in_node(kv.value)
}


Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]

    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]

    check_keyvalue(attr)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Configuration uses wildcard IP allowing connections from any network interface. (CWE-1327)"
    }
}


Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "Attribute"
    check_keyvalue(node)

    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Configuration uses wildcard IP allowing connections from any network interface. (CWE-1327)"
    }
}


Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "Variable"
    check_keyvalue(node)

    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Configuration uses wildcard IP allowing connections from any network interface. (CWE-1327)"
    }
}


Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "KeyValue"
    has_bind_context(node.name)
    find_wildcard_in_node(node.value)

    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Configuration uses wildcard IP allowing connections from any network interface. (CWE-1327)"
    }
}


Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, hash])
    hash.ir_type == "Hash"

    some i
    hash.value[i].key.ir_type == "String"
    has_bind_context(hash.value[i].key.value)

    val := hash.value[i].value
    find_wildcard_in_node(val)

    result := {
        "type": "sec_invalid_bind",
        "element": hash.value[i],
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Configuration uses wildcard IP allowing connections from any network interface. (CWE-1327)"
    }
}


Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, hash])
    hash.ir_type == "Hash"

    some i
    hash.value[i].key.ir_type == "VariableReference"
    has_bind_context(hash.value[i].key.value)

    val := hash.value[i].value
    find_wildcard_in_node(val)

    result := {
        "type": "sec_invalid_bind",
        "element": hash.value[i],
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - Configuration uses wildcard IP allowing connections from any network interface. (CWE-1327)"
    }
}