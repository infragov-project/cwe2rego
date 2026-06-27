package glitch

import data.glitch_lib

is_user_input_source(node) {
    node.ir_type == "VariableReference"
}

has_user_input_source(node) {
    walk(node, [_, n])
    is_user_input_source(n)
}

is_user_input_access(node) {
    node.ir_type == "Access"
    walk(node, [_, n])
    is_user_input_source(n)
}

is_multi_branch_conditional(stmt) {
    stmt.ir_type == "ConditionalStatement"
    stmt.type == 2
    stmt.else_statement != null
} else {
    stmt.ir_type == "ConditionalStatement"
    stmt.type == 2
    stmt.is_top == true
} else {
    stmt.ir_type == "ConditionalStatement"
    stmt.type == 1
    stmt.is_top == true
    stmt.else_statement != null
    stmt.else_statement.ir_type == "ConditionalStatement"
}

has_enumerated_condition(stmt) {
    stmt.condition.ir_type == "Equal"
} else {
    stmt.condition.ir_type == "In"
} else {
    stmt.condition.ir_type == "Or"
}

condition_has_external_input(stmt) {
    has_user_input_source(stmt.condition)
} else {
    is_user_input_access(stmt.condition.left)
} else {
    is_user_input_access(stmt.condition.right)
}

follow_else_chain_to_end(stmt) = end_stmt {
    stmt.else_statement == null
    end_stmt := stmt
} else = end_stmt {
    stmt.else_statement.ir_type != "ConditionalStatement"
    end_stmt := stmt
} else = end_stmt {
    end_stmt := follow_else_chain_to_end(stmt.else_statement)
}

has_default_in_chain(stmt) {
    stmt.is_default == true
} else {
    stmt.else_statement.ir_type == "ConditionalStatement"
    has_default_in_chain(stmt.else_statement)
}

nested_switch_lacks_default(stmt) {
    stmt.ir_type == "ConditionalStatement"
    stmt.type == 2
    not has_default_in_chain(stmt)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, stmt])
    stmt.ir_type == "ConditionalStatement"
    stmt.is_top == true
    
    is_multi_branch_conditional(stmt)
    has_enumerated_condition(stmt)
    condition_has_external_input(stmt)
    not has_default_in_chain(stmt)
    
    result := {
        "type": "sec_no_default_switch",
        "element": stmt,
        "path": parent.path,
        "description": "Missing default case in multi-branch conditional - Conditional structures should have a default/fallback case to handle unexpected input values and prevent undefined behavior. (CWE-478)"
    }
}