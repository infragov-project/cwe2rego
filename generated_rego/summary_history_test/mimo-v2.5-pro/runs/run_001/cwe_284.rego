package glitch

import data.glitch_lib

# Strong bind-related patterns (always indicate binding when found as substring)
strong_bind_regex := "(?i)(bind|listen)"

# Weak bind-related names - matches as standalone word or when separated by
# non-alpha characters (brackets, dashes, underscores, dots, colons, etc.)
# Handles Chef symbols like ":ip", compound names like "default[:redis][:server][:addr]",
# while avoiding false positives like "hosts"
weak_bind_regex := "(?i)(^|[^a-zA-Z])(ip|address|addr|host)($|[^a-zA-Z])"

# Dangerous values for network binding
dangerous_value_regex := "(?i)^(0\\.0\\.0\\.0|::|\\*|any|all|0\\.0\\.0\\.0/0|::/0)$"

is_bind_name(name) {
    regex.match(strong_bind_regex, name)
} else {
    regex.match(weak_bind_regex, name)
}

is_dangerous_value(val) {
    val.ir_type == "String"
    regex.match(dangerous_value_regex, val.value)
}

get_key_name(key) = name {
    key.ir_type == "String"
    name := key.value
} else = name {
    key.ir_type == "VariableReference"
    name := key.value
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    name := get_key_name(entry.key)
    is_bind_name(name)
    is_dangerous_value(entry.value)
    result := {
        "type": "sec_invalid_bind",
        "element": entry.value,
        "path": parent.path,
        "description": "Network binding configured to unrestricted address, exposing service to all interfaces (CWE-284, CWE-862)",
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    is_bind_name(node.name)
    is_dangerous_value(node.value)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Network binding configured to unrestricted address, exposing service to all interfaces (CWE-284, CWE-862)",
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    is_bind_name(node.name)
    is_dangerous_value(node.value)
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Network binding configured to unrestricted address, exposing service to all interfaces (CWE-284, CWE-862)",
    }
}