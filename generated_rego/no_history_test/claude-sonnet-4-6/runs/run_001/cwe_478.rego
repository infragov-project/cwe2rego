package glitch

import data.glitch_lib

is_default_node(cond) {
    cond.is_default == true
}

is_default_node(cond) {
    cond.condition.ir_type == "Null"
}

chain_has_default(cond) {
    is_default_node(cond)
}

chain_has_default(cond) {
    is_default_node(cond.else_statement)
}

chain_has_default(cond) {
    is_default_node(cond.else_statement.else_statement)
}

chain_has_default(cond) {
    is_default_node(cond.else_statement.else_statement.else_statement)
}

chain_has_default(cond) {
    is_default_node(cond.else_statement.else_statement.else_statement.else_statement)
}

chain_has_default(cond) {
    is_default_node(cond.else_statement.else_statement.else_statement.else_statement.else_statement)
}

has_bool_case(cond, val) {
    cond.condition.ir_type == "Equal"
    cond.condition.right.ir_type == "Boolean"
    cond.condition.right.value == val
}

has_bool_case(cond, val) {
    cond.else_statement.condition.ir_type == "Equal"
    cond.else_statement.condition.right.ir_type == "Boolean"
    cond.else_statement.condition.right.value == val
}

has_bool_case(cond, val) {
    cond.else_statement.else_statement.condition.ir_type == "Equal"
    cond.else_statement.else_statement.condition.right.ir_type == "Boolean"
    cond.else_statement.else_statement.condition.right.value == val
}

is_boolean_exhaustive(cond) {
    has_bool_case(cond, true)
    has_bool_case(cond, false)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    conds := glitch_lib.all_conditional_statements(parent)
    cond := conds[_]
    cond.is_top == true
    cond.type == "SWITCH"

    not chain_has_default(cond)
    not is_boolean_exhaustive(cond)

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Conditional statements should include a default/else branch to handle unexpected inputs. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    conds := glitch_lib.all_conditional_statements(parent)
    cond := conds[_]
    cond.is_top == true
    cond.type == "IF"

    cond.else_statement.ir_type == "ConditionalStatement"
    cond.else_statement.is_default == false
    cond.else_statement.condition.ir_type != "Null"

    not chain_has_default(cond)

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Conditional statements should include a default/else branch to handle unexpected inputs. (CWE-478)"
    }
}