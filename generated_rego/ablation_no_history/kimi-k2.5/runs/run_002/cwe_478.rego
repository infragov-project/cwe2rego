package glitch

import data.glitch_lib

is_switch_type(cond_stmt) {
    cond_stmt.type == "SWITCH"
}

is_switch_type(cond_stmt) {
    cond_stmt.type == 2
}

is_if_type(cond_stmt) {
    cond_stmt.type == "IF"
}

is_if_type(cond_stmt) {
    cond_stmt.type == 1
}

is_default_case(cond) {
    cond.is_default == true
}

find_all_conditional_statements(node) = conditions {
    conditions = {n |
        walk(node, [_, n])
        n.ir_type == "ConditionalStatement"
    }
}

has_default_in_chain(cond) {
    is_default_case(cond)
}

has_default_in_chain(cond) {
    cond.else_statement
    is_default_case(cond.else_statement)
}

has_default_in_chain(cond) {
    cond.else_statement
    cond.else_statement.ir_type == "ConditionalStatement"
    has_default_in_chain(cond.else_statement)
}

missing_default_in_switch_chain(cond) {
    is_switch_type(cond)
    not has_default_in_chain(cond)
}

missing_default_in_if_chain(cond) {
    is_if_type(cond)
    not cond.else_statement
}

missing_default_in_if_chain(cond) {
    is_if_type(cond)
    cond.else_statement
    cond.else_statement.ir_type == "ConditionalStatement"
    is_if_type(cond.else_statement)
    missing_default_in_if_chain(cond.else_statement)
}

missing_default_in_if_chain(cond) {
    is_if_type(cond)
    cond.else_statement
    cond.else_statement.ir_type == "ConditionalStatement"
    is_switch_type(cond.else_statement)
    missing_default_in_switch_chain(cond.else_statement)
}

is_lookup_without_default(fn) {
    fn.ir_type == "FunctionCall"
    regex.match("(?i)^(lookup|map|find|get|select)$", fn.name)
    count(fn.args) < 3
}

is_lookup_without_default(fn) {
    fn.ir_type == "MethodCall"
    regex.match("(?i)^(lookup|map|find|get|select)$", fn.method)
    count(fn.args) < 2
}

contains_lookup_without_default(expr) {
    walk(expr, [_, n])
    is_lookup_without_default(n)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conds := find_all_conditional_statements(parent)
    cond := conds[_]
    
    is_switch_type(cond)
    cond.is_top == true
    missing_default_in_switch_chain(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Conditional statement must have a default/fallback branch to handle unhandled values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conds := find_all_conditional_statements(parent)
    cond := conds[_]
    
    is_if_type(cond)
    cond.is_top == true
    missing_default_in_if_chain(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Conditional statement must have a default/fallback branch to handle unhandled values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    contains_lookup_without_default(var.value)
    
    result := {
        "type": "sec_no_default_switch",
        "element": var,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Lookup function must have a default/fallback value to handle unhandled values. (CWE-478)"
    }
}