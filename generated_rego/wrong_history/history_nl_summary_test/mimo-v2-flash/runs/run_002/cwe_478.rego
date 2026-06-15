package glitch

import data.glitch_lib

has_default_case(cond) = true {
    cond.is_default == true
} else {
    cond.else_statement != null
    has_default_case(cond.else_statement)
} else {
    false
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    
    conditional := conditionals[_]
    conditional.type in {"SWITCH", "IF"}
    conditional.is_top == true
    
    not has_default_case(conditional)
    
    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression (CWE-478)"
    }
}