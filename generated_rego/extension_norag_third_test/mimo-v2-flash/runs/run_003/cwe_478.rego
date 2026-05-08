package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    walk(input, [path, cond])
    cond.ir_type == "ConditionalStatement"
    cond.is_top == true
    cond.type == 1  # IF type (from enum)
    cond.else_statement == null
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": input.name,
        "description": "Missing default case in conditional expression - Unhandled cases can cause resource misconfigurations. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    walk(input, [path, cond])
    cond.ir_type == "ConditionalStatement"
    cond.is_top == true
    cond.type == 2  # SWITCH type (from enum)
    
    # Check if there's no default case in the switch chain
    not switch_has_default(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": input.name,
        "description": "Missing default case in switch expression - Unhandled cases can cause resource misconfigurations. (CWE-478)"
    }
}

# Helper to check if a switch has a default case
switch_has_default(switch) {
    current := switch
    max_iterations := 100
    count := 0
    
    count < max_iterations
    current != null
    current.ir_type == "ConditionalStatement"
    current.is_default == true
} else {
    current := switch
    max_iterations := 100
    count := 0
    
    count < max_iterations
    current != null
    current.ir_type == "ConditionalStatement"
    current.else_statement != null
    
    # Move to next in chain
    current = current.else_statement
    count = count + 1
    
    # Recursively check the rest of the chain
    switch_has_default(current)
}

# Detect missing default in ternary chains (nested Equal operations without fallback)
Glitch_Analysis[result] {
    walk(input, [path, node])
    node.ir_type == "Equal"
    
    # Check if this Equal node is part of a conditional statement without else branch
    is_in_conditional_without_else(node)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": input.name,
        "description": "Incomplete ternary chain without fallback - Unhandled cases can cause misconfigurations. (CWE-478)"
    }
}

# Helper to check if a node is in a conditional statement without else branch
is_in_conditional_without_else(node) {
    walk(input, [path, parent])
    parent.ir_type == "ConditionalStatement"
    parent.else_statement == null
    walk(parent, [_, child])
    child == node
}

# Detect missing default in map/dictionary lookups
Glitch_Analysis[result] {
    walk(input, [path, node])
    node.ir_type == "FunctionCall"
    
    # Check for common lookup functions without default parameter
    regex.match("(?i)(lookup|get|index|fetch|fetch_or)", node.name)
    
    # Check if the function has fewer than 3 arguments (no default)
    count(node.args) < 3
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": input.name,
        "description": "Missing default value in map lookup - Unhandled keys can cause failures. (CWE-478)"
    }
}