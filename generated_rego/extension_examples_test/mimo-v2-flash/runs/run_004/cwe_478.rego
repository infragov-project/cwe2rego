package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all conditional statements in the parent
    conditions := glitch_lib.all_conditional_statements(parent)
    
    # Find top-level conditional statements (switch/match/when expressions)
    top_cond := conditions[_]
    top_cond.is_top == true
    top_cond.type == 2  # SWITCH type
    
    # Check if this conditional has multiple explicit cases by collecting all conditionals in the chain
    # We look for chains of conditionals connected via else_statement
    chain := collect_chain(top_cond)
    
    # Filter non-default conditionals in the chain
    non_default_conditions := [c | c := chain[_]; c.is_default == false]
    count(non_default_conditions) >= 2  # Multiple explicit cases
    
    # Check if there's no default case in the entire chain
    default_conditions := [c | c := chain[_]; c.is_default == true]
    count(default_conditions) == 0
    
    result := {
        "type": "sec_no_default_switch",
        "element": top_cond,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression (CWE-478)"
    }
}

# Recursive function to collect the entire chain of conditionals
collect_chain(conditional) = chain {
    conditional.else_statement != null
    rest := collect_chain(conditional.else_statement)
    chain := [conditional] + rest
} else {
    chain := [conditional]
}