package glitch

import data.glitch_lib

# Rule for detecting SWITCH statements without a default case
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    cond.ir_type == "ConditionalStatement"
    cond.type == 2  # SWITCH type
    cond.is_top == true
    
    # Check if there is no default case in the switch
    default_exists := false
    some stmt in cond.statements
    stmt.ir_type == "ConditionalStatement"
    stmt.is_default == true
    default_exists := true
    
    not default_exists
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in SWITCH statement. (CWE-478)"
    }
}

# Rule for detecting missing default in IF chains
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    cond.ir_type == "ConditionalStatement"
    cond.type == 1  # IF type
    cond.is_top == true
    
    # Check if the IF chain ends without a default else
    current := cond
    has_default := false
    
    # Iterate through the chain using set comprehension
    some c in collect_all_conditions(cond)
    c.is_default == true
    has_default := true
    
    not has_default
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in IF chain. (CWE-478)"
    }
}

# Helper to collect all conditions in an IF chain without recursion
collect_all_conditions(cond) := {c | 
    c := cond
} | {c | 
    cond.else_statement != null
    c := collect_all_conditions(cond.else_statement)[_]
}