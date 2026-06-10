package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Find all conditional statements in the parent
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]
    
    # Check if this is a top-level switch/if statement without default
    conditional.is_top == true
    conditional.type == "SWITCH"
    
    # Verify no default case exists in the chain
    not has_default_case(conditional)
    
    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Unhandled states can lead to undefined behavior. (CWE-478)"
    }
}

# Helper to check if a conditional chain has a default case
has_default_case(conditional) {
    conditional.is_default == true
} else {
    conditional.else_statement != null
    has_default_case(conditional.else_statement)
}