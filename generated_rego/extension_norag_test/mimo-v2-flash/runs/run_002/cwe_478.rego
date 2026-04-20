package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    top_conditional := conditionals[_]
    top_conditional.is_top == true
    top_conditional.type == "IF"
    
    # Check if the conditional chain has a default case
    has_default := false
    
    # Traverse the else_statement chain to check for default
    current := top_conditional
    while {
        current.is_default == true {
            has_default := true
            break
        }
        current.else_statement != null {
            current := current.else_statement
        }
        break
    }
    
    not has_default
    
    result := {
        "type": "sec_no_default_switch",
        "element": top_conditional,
        "path": parent.path,
        "description": "Missing default case in conditional expression - This could lead to unexpected behavior for unhandled values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    top_conditional := conditionals[_]
    top_conditional.is_top == true
    top_conditional.type == "SWITCH"
    
    # Check if the conditional chain has a default case
    has_default := false
    
    # Traverse the else_statement chain to check for default
    current := top_conditional
    while {
        current.is_default == true {
            has_default := true
            break
        }
        current.else_statement != null {
            current := current.else_statement
        }
        break
    }
    
    not has_default
    
    result := {
        "type": "sec_no_default_switch",
        "element": top_conditional,
        "path": parent.path,
        "description": "Missing default case in conditional expression - This could lead to unexpected behavior for unhandled values. (CWE-478)"
    }
}