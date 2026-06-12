package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_conditional := glitch_lib.all_conditional_statements(parent)
    top_conditionals := {c | c := all_conditional; c.is_top}
    top_conditional := top_conditionals[_]
    
    not has_default_in_chain(top_conditional)
    
    result := {
        "type": "sec_no_default_switch",
        "element": top_conditional,
        "path": parent.path,
        "description": "Conditional statement (if/switch) missing a default case. (CWE-478)"
    }
}

has_default_in_chain(conditional) {
    conditional.is_default
}

has_default_in_chain(conditional) {
    conditional.else_statement != null
    has_default_in_chain(conditional.else_statement)
}