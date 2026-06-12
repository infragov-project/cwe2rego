package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    
    top_conditionals := {c | c := conditionals[_]; c.is_top == true}
    top := top_conditionals[_]
    
    not has_default_in_chain(top)
    
    result := {
        "type": "sec_no_default_switch",
        "element": top,
        "path": parent.path,
        "description": "Missing default case in multi-condition expression - Unhandled edge cases may cause unexpected behavior. (CWE-478)"
    }
}

has_default_in_chain(c) {
    c.is_default == true
}

has_default_in_chain(c) {
    c.else_statement != null
    has_default_in_chain(c.else_statement)
}