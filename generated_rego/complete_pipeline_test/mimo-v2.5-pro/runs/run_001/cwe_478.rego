package glitch

import data.glitch_lib

has_default_in_chain(node) {
    node.is_default == true
}

has_default_in_chain(node) {
    node.else_statement != null
    node.else_statement.is_default == true
}

has_default_in_chain(node) {
    node.else_statement != null
    node.else_statement.else_statement != null
    node.else_statement.else_statement.is_default == true
}

has_default_in_chain(node) {
    node.else_statement != null
    node.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.is_default == true
}

has_default_in_chain(node) {
    node.else_statement != null
    node.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.is_default == true
}

has_default_in_chain(node) {
    node.else_statement != null
    node.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement.is_default == true
}

has_default_in_chain(node) {
    node.else_statement != null
    node.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.is_default == true
}

has_default_in_chain(node) {
    node.else_statement != null
    node.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.is_default == true
}

has_default_in_chain(node) {
    node.else_statement != null
    node.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.is_default == true
}

has_default_in_chain(node) {
    node.else_statement != null
    node.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement != null
    node.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.else_statement.is_default == true
}

is_complete_boolean_ternary(node) {
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
    not node.is_default
    node.condition.ir_type == "Equal"
    node.condition.right.ir_type == "Boolean"
    node.else_statement != null
    not node.else_statement.is_default
    node.else_statement.condition.ir_type == "Equal"
    node.else_statement.condition.right.ir_type == "Boolean"
    node.condition.right.value != node.else_statement.condition.right.value
    node.else_statement.else_statement == null
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
    node.is_top == true
    not node.is_default

    not has_default_in_chain(node)
    not is_complete_boolean_ternary(node)

    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Ensure that conditional logic includes a default/fallback branch for unexpected values. (CWE-478)"
    }
}