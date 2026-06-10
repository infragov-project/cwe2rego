package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Find all conditional statements
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    
    # Check if it's a SWITCH type without default case
    cond.type == "SWITCH"
    cond.is_top == true
    not has_default_case(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in conditional expression - All possible states should be handled. (CWE-478)"
    }
}

# Helper function to check if a conditional chain has a default case
has_default_case(cond) {
    # Check if current condition is default
    cond.is_default == true
} else {
    # Check if any else_statement in the chain is default
    is_default_else(cond.else_statement)
}

# Recursive helper to check if an else branch is or contains a default
is_default_else(statement) {
    statement.is_default == true
} else {
    statement.else_statement != null
    is_default_else(statement.else_statement)
} else {
    # Handle nested conditionals within the statements
    walk(statement, [path, node])
    node.ir_type == "ConditionalStatement"
    node.is_default == true
}