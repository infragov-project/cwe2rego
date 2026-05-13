package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]
    conditional.is_top == true
    conditional.type == "IF"
    conditional.else_statement == null

    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Missing default case in conditional expression - This can lead to unhandled edge cases and undefined behavior. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]
    conditional.is_top == true
    conditional.type == "SWITCH"
    
    # Check if there's no default case in the switch chain
    not has_switch_default(conditional)

    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Missing default case in conditional expression - This can lead to unhandled edge cases and undefined behavior. (CWE-478)"
    }
}

has_switch_default(conditional) {
    conditional.is_default == true
}

has_switch_default(conditional) {
    conditional.else_statement != null
    # Check all conditional statements within the else_statement
    some else_cond
    else_cond := glitch_lib.all_conditional_statements(conditional.else_statement)[_]
    has_switch_default(else_cond)
}