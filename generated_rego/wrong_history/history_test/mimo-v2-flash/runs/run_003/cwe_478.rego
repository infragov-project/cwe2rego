package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditional_statements := glitch_lib.all_conditional_statements(parent)
    cs := conditional_statements[_]
    
    cs.is_default == false
    cs.is_top == true
    
    not (cs.else_statement != null and cs.else_statement.is_default == true)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cs,
        "path": parent.path,
        "description": "Missing default case in conditional statement - This may lead to undefined behavior when an unexpected value is encountered. (CWE-478)"
    }
}