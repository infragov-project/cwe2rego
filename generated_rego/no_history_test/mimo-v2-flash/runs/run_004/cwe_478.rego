package glitch

import data.glitch_lib

collect_conditions(cond, acc) = result {
    cond.else_statement != null
    result := collect_conditions(cond.else_statement, acc | {cond})
} else {
    result := acc | {cond}
}

has_default_in_chain(cond) {
    conditions := collect_conditions(cond, set())
    condition := conditions[_]
    condition.is_default == true
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    switch_cond := conditions[_]
    switch_cond.type == "SWITCH"
    switch_cond.is_top == true
    not has_default_in_chain(switch_cond)

    result := {
        "type": "sec_no_default_switch",
        "element": switch_cond,
        "path": parent.path,
        "description": "Missing default case in switch expression - Missing default branch to handle unexpected values (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    if_cond := conditions[_]
    if_cond.type == "IF"
    if_cond.is_top == true
    not has_default_in_chain(if_cond)

    result := {
        "type": "sec_no_default_switch",
        "element": if_cond,
        "path": parent.path,
        "description": "Missing else branch in if-elif chain - Missing default branch to handle unexpected conditions (CWE-478)"
    }
}