package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    conditions := glitch_lib.all_conditional_statements(parent)
    node := conditions[_]
    node.type == "SWITCH"

    not has_default_branch(node)

    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in switch statement - Switch statement without default case may cause undefined behavior for unhandled cases. (CWE-478)"
    }
}

has_default_branch(cond) {
    cond.is_default == true
}

has_default_branch(cond) {
    cond.else_statement
    cond.else_statement.ir_type == "ConditionalStatement"
    cond.else_statement.is_default == true
}

has_default_branch(cond) {
    cond.else_statement
    cond.else_statement.ir_type == "ConditionalStatement"
    cond.else_statement.condition.ir_type == "Null"
}

has_default_branch(cond) {
    cond.else_statement
    cond.else_statement.ir_type == "ConditionalStatement"
    cond.else_statement.condition.ir_type == "Undef"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    conditions := glitch_lib.all_conditional_statements(parent)
    node := conditions[_]
    node.type == "IF"
    node.is_top == true

    count_if_branches(node, 0, n)
    n >= 3
    not has_else_branch(node)

    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in multi-branch if-elsif chain - If-elsif chain with 3+ branches without else may cause undefined behavior for unhandled cases. (CWE-478)"
    }
}

count_if_branches(cond, acc, n) {
    not cond.else_statement
    n := acc + 1
}

count_if_branches(cond, acc, n) {
    cond.else_statement
    cond.else_statement.ir_type != "ConditionalStatement"
    n := acc + 1
}

count_if_branches(cond, acc, n) {
    cond.else_statement
    cond.else_statement.ir_type == "ConditionalStatement"
    cond.else_statement.type != "IF"
    n := acc + 1
}

count_if_branches(cond, acc, n) {
    cond.else_statement
    cond.else_statement.ir_type == "ConditionalStatement"
    cond.else_statement.type == "IF"
    new_acc := acc + 1
    count_if_branches(cond.else_statement, new_acc, n)
}

has_else_branch(cond) {
    cond.else_statement
    cond.else_statement.ir_type == "ConditionalStatement"
    cond.else_statement.is_default == true
}

has_else_branch(cond) {
    cond.else_statement
    cond.else_statement.ir_type == "ConditionalStatement"
    cond.else_statement.condition.ir_type == "Null"
}

has_else_branch(cond) {
    cond.else_statement
    cond.else_statement.ir_type == "ConditionalStatement"
    cond.else_statement.condition.ir_type == "Undef"
}

has_else_branch(cond) {
    cond.else_statement
    cond.else_statement.ir_type != "ConditionalStatement"
    cond.else_statement.ir_type
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    vars := glitch_lib.all_variables(parent)
    node := vars[_]

    node.value.ir_type == "Hash"

    not hash_has_default_key(node.value)

    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default key in hash lookup - Hash used as lookup table without default key may cause undefined behavior for unhandled lookup keys. (CWE-478)"
    }
}

hash_has_default_key(h) {
    some key
    h.value[key]
    key.ir_type == "String"
    lower(key.value) == {"default", "else", "_", "fallback", "other", "*", ""}[_]
}