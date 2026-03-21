package glitch

import data.glitch_lib

has_default_case(conditional) := true if {
    conditional.is_default == true
}

has_default_case(conditional) := true if {
    else_stmt := conditional.else_statement
    else_stmt != null
    else_stmt.ir_type == "ConditionalStatement"
    has_default_case(else_stmt)
}

has_default_case(conditional) := true if {
    some stmt in conditional.statements
    stmt.ir_type == "ConditionalStatement"
    has_default_case(stmt)
}

has_else_branch(conditional) := true if {
    conditional.else_statement != null
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]
    conditional.ir_type == "ConditionalStatement"
    conditional.type == "SWITCH"
    conditional.is_top == true
    not has_default_case(conditional)
    
    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Missing default case in switch statement - Conditional logic lacks a default branch for unhandled values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]
    conditional.ir_type == "ConditionalStatement"
    conditional.type == "IF"
    conditional.is_top == true
    not has_else_branch(conditional)
    
    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Missing else branch in if statement - Conditional logic lacks a fallback for unhandled values. (CWE-478)"
    }
}