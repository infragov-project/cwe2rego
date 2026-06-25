package glitch

import data.glitch_lib

has_default_case(switch_node) {
    walk(switch_node, [_, n])
    n.ir_type == "ConditionalStatement"
    n.is_default == true
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    conditions := glitch_lib.all_conditional_statements(parent)
    node := conditions[_]

    node.type == "SWITCH"
    node.is_top == true

    not has_default_case(node)

    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing Default Case in Multiple Condition Expression - Switch/case statements should include a default case to handle all unexpected values. (CWE-478)"
    }
}