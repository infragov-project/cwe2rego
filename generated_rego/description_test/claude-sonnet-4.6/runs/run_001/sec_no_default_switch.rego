package glitch

import data.glitch_lib

is_switch(cond) { cond.type == "SWITCH" }
is_switch(cond) { cond.type == 2 }

is_if_type(cond) { cond.type == "IF" }
is_if_type(cond) { cond.type == 1 }

path_only_else_chain(path) {
    count([x | x := path[_]; x != "else_statement"]) == 0
}

has_real_condition(cond) {
    cond.condition != null
    not cond.condition.ir_type == "Null"
    not cond.condition.ir_type == "Undef"
}

chain_has_default(cond) {
    walk(cond, [path, node])
    path_only_else_chain(path)
    node.ir_type == "ConditionalStatement"
    node.is_default == true
}

chain_has_default(cond) {
    walk(cond, [path, node])
    path_only_else_chain(path)
    count(path) > 0
    node.ir_type == "ConditionalStatement"
    node.is_default == false
    node.is_top == false
    not has_real_condition(node)
}

boolean_selector(cond) {
    is_switch(cond)
    cond.condition.ir_type == "Equal"
    cond.condition.right.ir_type == "Boolean"
    cond.else_statement.ir_type == "ConditionalStatement"
    cond.else_statement.condition.ir_type == "Equal"
    cond.else_statement.condition.right.ir_type == "Boolean"
    cond.condition.right.value != cond.else_statement.condition.right.value
    not cond.else_statement.else_statement.ir_type == "ConditionalStatement"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    cond.is_top == true
    is_switch(cond)
    not chain_has_default(cond)
    not boolean_selector(cond)
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Switch/Case without default branch - A switch/case construct lacks a default/fallback branch, creating unhandled paths when inputs match no defined case. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    cond.is_top == true
    is_if_type(cond)
    cond.else_statement.ir_type == "ConditionalStatement"
    cond.else_statement.is_default == false
    has_real_condition(cond.else_statement)
    not chain_has_default(cond)
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "If/Elif chain without default else branch - A conditional chain lacks a terminal else clause, leaving unhandled paths when no condition is matched. (CWE-478)"
    }
}