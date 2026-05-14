package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for IF conditionals without else branch
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    cond.ir_type == "ConditionalStatement"
    cond.type == 1  # IF type
    cond.is_top == true
    cond.else_statement == null
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing else branch in conditional expression - The if statement does not handle all cases. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for SWITCH conditionals without default case
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    cond.ir_type == "ConditionalStatement"
    cond.type == 2  # SWITCH type
    cond.is_top == true
    
    # Check that no default case exists in the chain
    # We can check this by ensuring no node in the chain has is_default=true
    # Since we're checking the top node and its entire chain, we use a helper rule
    not has_default_case(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in switch expression - The switch statement does not have a default case. (CWE-478)"
    }
}

# Helper rule to check if a conditional chain has a default case
has_default_case(cond) {
    cond.is_default == true
}

has_default_case(cond) {
    cond.else_statement != null
    has_default_case(cond.else_statement)
}