package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    condition := conditions[_]
    condition.is_top == true
    condition.is_default == false
    condition.type in {"IF", "SWITCH"}

    not has_default_in_chain(condition)

    result := {
        "type": "sec_no_default_switch",
        "element": condition,
        "path": parent.path,
        "description": "Missing default case in conditional statement (CWE-478)"
    }
}

has_default_in_chain(cond) {
    cond.is_default == true
} else {
    cond.else_statement != null
    has_default_in_chain(cond.else_statement)
}