package glitch

import data.glitch_lib

has_default_case(cond) {
    walk(cond, [_, node])
    node.ir_type == "ConditionalStatement"
    node.is_default == true
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]

    cond.is_top == true
    not has_default_case(cond)

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Conditional expressions should include a default/else branch to handle unexpected values. (CWE-478)"
    }
}