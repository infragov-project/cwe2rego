package glitch

import data.glitch_lib

is_switch_type(stmt) {
    stmt.type == "SWITCH"
}

switch_chain_has_default(switch_node) {
    walk(switch_node, [path, n])
    n.ir_type == "ConditionalStatement"
    n.is_default == true
    count({k | k := path[_]; is_string(k); k != "else_statement"}) == 0
}

switch_chain_has_non_boolean_condition(switch_node) {
    walk(switch_node, [path, n])
    n.ir_type == "ConditionalStatement"
    count({k | k := path[_]; is_string(k); k != "else_statement"}) == 0
    n.condition.ir_type != "Null"
    n.condition.right.ir_type != "Boolean"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    conditions := glitch_lib.all_conditional_statements(parent)
    switch_stmt := conditions[_]

    switch_stmt.is_top == true
    is_switch_type(switch_stmt)

    not switch_chain_has_default(switch_stmt)
    switch_chain_has_non_boolean_condition(switch_stmt)

    result := {
        "type": "sec_no_default_switch",
        "element": switch_stmt.condition.left,
        "path": parent.path,
        "description": "Missing Default Case in Multiple Condition Expression - Switch statements should include a default case to handle unexpected values and prevent undefined program states. (CWE-478)"
    }
}