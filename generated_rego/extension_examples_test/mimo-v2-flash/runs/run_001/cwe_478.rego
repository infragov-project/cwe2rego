package glitch

import data.glitch_lib

has_default[cond] {
    cond.ir_type == "ConditionalStatement"
    cond.is_default == true
}

has_default[cond] {
    cond.ir_type == "ConditionalStatement"
    cond.else_statement != null
    cond.else_statement.is_default == true
}

has_default[cond] {
    cond.ir_type == "ConditionalStatement"
    cond.else_statement != null
    cond.else_statement.else_statement != null
    cond.else_statement.else_statement.is_default == true
}

has_default[cond] {
    cond.ir_type == "ConditionalStatement"
    cond.else_statement != null
    cond.else_statement.else_statement != null
    cond.else_statement.else_statement.else_statement != null
    cond.else_statement.else_statement.else_statement.is_default == true
}

has_default[cond] {
    cond.ir_type == "ConditionalStatement"
    cond.else_statement != null
    cond.else_statement.else_statement != null
    cond.else_statement.else_statement.else_statement != null
    cond.else_statement.else_statement.else_statement.else_statement != null
    cond.else_statement.else_statement.else_statement.else_statement.is_default == true
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    cond.is_top == true
    cond.type == 1
    not has_default[cond]

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in conditional expression - The conditional expression does not handle all possible input values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    cond.is_top == true
    cond.type == 2
    not has_default[cond]

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in conditional expression - The conditional expression does not handle all possible input values. (CWE-478)"
    }
}