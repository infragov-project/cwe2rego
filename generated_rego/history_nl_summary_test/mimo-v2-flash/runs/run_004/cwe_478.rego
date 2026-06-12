package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]
    conditional.type == "SWITCH"
    conditional.is_top == true
    not has_default_branch(conditional)
    not is_ternary_operator(conditional)
    
    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Missing default condition in switch statement - Absence of default case can lead to unhandled scenarios and security gaps. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]
    conditional.type == "IF"
    conditional.is_top == true
    not conditional.else_statement
    is_part_of_if_chain(conditional, parent, conditionals)
    
    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Missing else condition in if-else chain - Absence of else clause can lead to unhandled scenarios and security gaps. (CWE-478)"
    }
}

has_default_branch(conditional) {
    conditional.type == "SWITCH"
    statement := conditional.statements[_]
    statement.ir_type == "ConditionalStatement"
    statement.is_default == true
}

has_default_branch(conditional) {
    conditional.type == "SWITCH"
    conditional.else_statement.is_default == true
}

has_default_branch(conditional) {
    conditional.type == "SWITCH"
    conditional.else_statement.else_statement.is_default == true
}

has_default_branch(conditional) {
    conditional.type == "SWITCH"
    conditional.else_statement.else_statement.else_statement.is_default == true
}

is_part_of_if_chain(conditional, parent, conditionals) {
    conditional.type == "IF"
    conditional.else_statement != null
    conditional.else_statement.type == "IF"
}

is_part_of_if_chain(conditional, parent, conditionals) {
    conditional.type == "IF"
    conditional.else_statement == null
    some other_cond
    other_cond = conditionals[_]
    other_cond.type == "IF"
    other_cond.else_statement == conditional
}

is_ternary_operator(conditional) {
    conditional.type == "SWITCH"
    conditional.else_statement != null
    conditional.else_statement.else_statement == null
    conditional.condition.ir_type == "Equal"
    conditional.condition.left.ir_type == "VariableReference"
    conditional.condition.right.ir_type == "Boolean"
    conditional.else_statement.condition.ir_type == "Equal"
    conditional.else_statement.condition.left.ir_type == "VariableReference"
    conditional.else_statement.condition.right.ir_type == "Boolean"
    conditional.else_statement.condition.left.value == conditional.condition.left.value
}