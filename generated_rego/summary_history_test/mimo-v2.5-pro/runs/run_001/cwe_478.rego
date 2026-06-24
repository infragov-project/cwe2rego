package glitch

import data.glitch_lib

is_else_chain_path(path) {
    count(path) > 0
    not has_non_else_step(path)
}

has_non_else_step(path) {
    path[_] != "else_statement"
}

chain_has_default(cond) {
    cond.is_default == true
}

chain_has_default(cond) {
    [path, node] := walk(cond)
    node.ir_type == "ConditionalStatement"
    node.is_default == true
    is_else_chain_path(path)
}

chain_has_default(cond) {
    [path, node] := walk(cond)
    node.ir_type == "ConditionalStatement"
    is_else_chain_path(path)
    node.else_statement == null
    is_fallback_condition(node.condition)
}

is_fallback_condition(expr) {
    expr.ir_type == "Null"
}

is_fallback_condition(expr) {
    expr.ir_type == "Undef"
}

is_fallback_condition(expr) {
    expr.ir_type == "Boolean"
    expr.value == true
}

is_boolean_exhaustive(cond) {
    cond.type == "SWITCH"
    has_bool_in_chain(cond, true)
    has_bool_in_chain(cond, false)
}

has_bool_in_chain(cond, val) {
    cond.condition.ir_type == "Equal"
    check_bool_side(cond.condition, val)
}

has_bool_in_chain(cond, val) {
    [path, node] := walk(cond)
    node.ir_type == "ConditionalStatement"
    is_else_chain_path(path)
    node.condition.ir_type == "Equal"
    check_bool_side(node.condition, val)
}

check_bool_side(expr, val) {
    expr.right.ir_type == "Boolean"
    expr.right.value == val
}

check_bool_side(expr, val) {
    expr.left.ir_type == "Boolean"
    expr.left.value == val
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]

    conditional.type == "SWITCH"
    conditional.is_top == true
    not conditional.is_default
    not chain_has_default(conditional)
    not is_boolean_exhaustive(conditional)

    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Missing default case in a switch statement - Always include a default case to handle unexpected inputs. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]

    conditional.type == "IF"
    conditional.is_top == true
    not conditional.is_default
    conditional.else_statement != null
    not chain_has_default(conditional)

    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Missing default case in conditional chain - Always include a default case to handle unexpected inputs. (CWE-478)"
    }
}