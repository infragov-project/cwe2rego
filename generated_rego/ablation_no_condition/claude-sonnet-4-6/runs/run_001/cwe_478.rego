package glitch

import data.glitch_lib

switch_has_default_in_chain(node) {
    walk(node, [path, child])
    child.ir_type == "ConditionalStatement"
    child.type == "SWITCH"
    child.is_default == true
    count({s | s := path[_]; s != "else_statement"}) == 0
}

switch_is_boolean_exhaustive(node) {
    node.condition.ir_type == "Equal"
    node.condition.right.ir_type == "Boolean"
    node.else_statement.condition.ir_type == "Equal"
    node.else_statement.condition.right.ir_type == "Boolean"
    node.condition.right.value != node.else_statement.condition.right.value
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    conditions := glitch_lib.all_conditional_statements(parent)
    node := conditions[_]

    node.type == "SWITCH"
    node.is_top == true

    not switch_has_default_in_chain(node)
    not switch_is_boolean_exhaustive(node)

    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Switch/match statements should always include a default case to handle unexpected values and prevent undefined behavior. (CWE-478)"
    }
}