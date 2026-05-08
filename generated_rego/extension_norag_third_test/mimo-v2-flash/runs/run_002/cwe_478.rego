package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conditionals := glitch_lib.all_conditional_statements(parent)
    top_conditional := conditionals[_]
    top_conditional.is_top == true
    top_conditional.is_default == false
    
    # Build list of conditionals in the chain by following else_statements
    chain := []
    current := top_conditional
    while current != null {
        chain := array.concat(chain, [current])
        current := current.else_statement
    }
    
    # Check if any conditional in the chain is a default
    has_default := false
    count_default := count([c | c := chain[_]; c.is_default == true])
    has_default = (count_default > 0)
    
    not has_default
    
    result := {
        "type": "sec_no_default_switch",
        "element": top_conditional,
        "path": parent.path,
        "description": "Conditional block without a default branch - This can lead to unhandled cases and potential security issues. (CWE-478)"
    }
}