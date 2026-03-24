package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]
    conditional.is_top == true
    
    not has_default_case(conditional)
    
    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Conditional statement without default case - This may lead to undefined behavior. (CWE-478)"
    }
}

has_default_case(conditional) {
    conditional.is_default == true
}

has_default_case(conditional) {
    conditional.else_statement != null
    conditional.else_statement.is_default == true
}

has_default_case(conditional) {
    conditional.else_statement != null
    conditional.else_statement.else_statement != null
    conditional.else_statement.else_statement.is_default == true
}

has_default_case(conditional) {
    conditional.else_statement != null
    conditional.else_statement.else_statement != null
    conditional.else_statement.else_statement.else_statement != null
    conditional.else_statement.else_statement.else_statement.is_default == true
}

has_default_case(conditional) {
    conditional.else_statement != null
    conditional.else_statement.else_statement != null
    conditional.else_statement.else_statement.else_statement != null
    conditional.else_statement.else_statement.else_statement.else_statement != null
    conditional.else_statement.else_statement.else_statement.else_statement.is_default == true
}

has_default_case(conditional) {
    conditional.else_statement != null
    conditional.else_statement.else_statement != null
    conditional.else_statement.else_statement.else_statement != null
    conditional.else_statement.else_statement.else_statement.else_statement != null
    conditional.else_statement.else_statement.else_statement.else_statement.else_statement != null
    conditional.else_statement.else_statement.else_statement.else_statement.else_statement.is_default == true
}