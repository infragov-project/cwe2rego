package glitch

import data.glitch_lib

chain_has_default(node) {
    node.is_default == true
}

chain_has_default(node) {
    node.else_statement.is_default == true
}

chain_has_default(node) {
    node.else_statement.else_statement.is_default == true
}

chain_has_default(node) {
    node.else_statement.else_statement.else_statement.is_default == true
}

chain_has_default(node) {
    node.else_statement.else_statement.else_statement.else_statement.is_default == true
}

chain_has_default(node) {
    node.else_statement.else_statement.else_statement.else_statement.else_statement.is_default == true
}

chain_has_default(node) {
    node.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.is_default == true
}

chain_has_default(node) {
    node.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.is_default == true
}

is_boolean_exhaustive_switch(node) {
    node.condition.right.ir_type == "Boolean"
    node.else_statement != null
    node.else_statement.condition.right.ir_type == "Boolean"
    node.else_statement.else_statement == null
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
    node.is_top == true
    count(path) > 0
    path[count(path) - 1] != "value"
    not chain_has_default(node)
    not is_boolean_exhaustive_switch(node)
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Conditional logic lacks a fallback/catch-all path, leaving unhandled states that may silently alter resource provisioning behavior. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, var_node])
    var_node.ir_type == "Variable"
    switch_node := var_node.value
    switch_node.ir_type == "ConditionalStatement"
    switch_node.type == "SWITCH"
    switch_node.is_top == true
    not chain_has_default(switch_node)
    not is_boolean_exhaustive_switch(switch_node)
    result := {
        "type": "sec_no_default_switch",
        "element": var_node,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Conditional logic lacks a fallback/catch-all path, leaving unhandled states that may silently alter resource provisioning behavior. (CWE-478)"
    }
}