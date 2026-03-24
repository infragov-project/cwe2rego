package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    cond := conditionals[_]
    cond.type == "SWITCH"
    cond.is_top == true
    
    # Check for missing default by collecting all conditions in the chain
    # and checking if none have is_default set to true
    chain_has_default := false
    current := cond
    while current != null {
        if current.is_default {
            chain_has_default := true
        }
        current := current.else_statement
    }
    
    not chain_has_default
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in switch statement - Unhandled scenarios may lead to misconfigurations or security gaps. (CWE-478)"
    }
}