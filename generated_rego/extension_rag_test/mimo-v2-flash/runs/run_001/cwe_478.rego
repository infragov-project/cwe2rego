package glitch

import data.glitch_lib

has_default_case(cond) := true if {
    cond.is_default == true
}

has_default_case(cond) := has_default_case(cond.else_statement) if {
    cond.else_statement != null
}

is_missing_default(cond) := true if {
    cond.is_top == true
    not has_default_case(cond)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    cond := conditionals[_]
    is_missing_default(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in conditional expression - Unhandled cases can lead to misconfigurations. (CWE-478)"
    }
}