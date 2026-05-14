package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all conditional statements in the parent
    all_conditionals := glitch_lib.all_conditional_statements(parent)
    
    # Find top-level SWITCH conditionals
    top_switches := {c | c := all_conditionals[_]; c.type == "SWITCH"; c.is_top == true}
    
    # For each top-level switch, check if it's missing a default case
    top_switch := top_switches[_]
    
    # Get the else_statement chain without recursion using iterative approach
    # We'll collect all conditionals in the chain by following else_statement
    chain := {top_switch}
    current := top_switch
    while current.else_statement != null {
        chain := chain | {current.else_statement}
        current := current.else_statement
    }
    
    # Check if any conditional in the chain has a default case
    has_default := count({c | c := chain[_]; c.is_default == true}) > 0
    
    # If no default case exists, this is a potential vulnerability
    not has_default
    
    # Also check if there are multiple non-default cases (switch-like pattern)
    non_default_cases := {c | c := chain[_]; c.is_default == false}
    
    # Only flag if there are at least 2 non-default cases (avoid single if/else)
    count(non_default_cases) >= 2
    
    result := {
        "type": "sec_no_default_switch",
        "element": top_switch,
        "path": parent.path,
        "description": "Missing default case in switch statement - The switch statement does not handle all possible inputs. (CWE-478)"
    }
}

# Additional rule to catch switches in variable assignments
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all variables in the parent
    variables := glitch_lib.all_variables(parent)
    
    # Find variables that have SWITCH conditionals as their value
    var_with_switch := {v | v := variables[_]; v.value.ir_type == "ConditionalStatement"; v.value.type == "SWITCH"}
    
    # For each such variable, check the switch for missing default
    var := var_with_switch[_]
    switch_cond := var.value
    
    # Get the else_statement chain without recursion
    chain := {switch_cond}
    current := switch_cond
    while current.else_statement != null {
        chain := chain | {current.else_statement}
        current := current.else_statement
    }
    
    # Check if any conditional in the chain has a default case
    has_default := count({c | c := chain[_]; c.is_default == true}) > 0
    
    # If no default case exists and there are multiple cases, this is a potential vulnerability
    not has_default
    
    # Also check if there are multiple non-default cases (switch-like pattern)
    non_default_cases := {c | c := chain[_]; c.is_default == false}
    count(non_default_cases) >= 2
    
    result := {
        "type": "sec_no_default_switch",
        "element": var,
        "path": parent.path,
        "description": "Missing default case in variable assignment switch - The switch statement does not handle all possible inputs. (CWE-478)"
    }
}