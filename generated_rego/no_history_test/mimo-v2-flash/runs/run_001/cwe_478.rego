package glitch

import data.glitch_lib

has_default_in_if_chain(cond) {
    cond.ir_type == "ConditionalStatement"
    cond.type == "IF"
    cond.else_statement != null
    cond.else_statement.is_default == true
} else {
    cond.ir_type == "ConditionalStatement"
    cond.type == "IF"
    cond.else_statement != null
    cond.else_statement.ir_type == "ConditionalStatement"
    cond.else_statement.type == "IF"
    has_default_in_if_chain(cond.else_statement)
}

has_default_in_switch(cond) {
    cond.ir_type == "ConditionalStatement"
    cond.type == "SWITCH"
    cond.else_statement != null
    cond.else_statement.is_default == true
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    condition := conditions[_]
    condition.ir_type == "ConditionalStatement"
    condition.type == "IF"
    condition.is_top == true
    condition.condition != null
    not has_default_in_if_chain(condition)
    result := {
        "type": "sec_no_default_switch",
        "element": condition,
        "path": parent.path,
        "description": "Missing else case in IF statement (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    condition := conditions[_]
    condition.ir_type == "ConditionalStatement"
    condition.type == "SWITCH"
    condition.is_top == true
    condition.condition != null
    not has_default_in_switch(condition)
    result := {
        "type": "sec_no_default_switch",
        "element": condition,
        "path": parent.path,
        "description": "Missing default case in switch statement (CWE-478)"
    }
}