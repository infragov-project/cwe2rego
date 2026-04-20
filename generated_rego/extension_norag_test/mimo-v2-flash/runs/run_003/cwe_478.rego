package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    cond.ir_type == "ConditionalStatement"
    cond.is_top == true
    cond.type == "SWITCH"
    
    # Check if there's no default case in the switch statement
    default_exists := count({s | s := cond.statements[_]; s.ir_type == "ConditionalStatement"; s.is_default == true}) > 0
    not default_exists
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in SWITCH statement. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    cond.ir_type == "ConditionalStatement"
    cond.is_top == true
    cond.type == "IF"
    
    # Check if the IF statement has an else_statement
    # If it doesn't, it's a missing default case
    not cond.else_statement
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing else branch in IF statement. (CWE-478)"
    }
}