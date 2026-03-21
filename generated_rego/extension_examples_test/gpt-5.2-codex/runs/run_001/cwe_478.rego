package glitch

import data.glitch_lib

lookup_function_names := {"lookup"}
lookup_method_names := {"fetch", "lookup"}

branch_is_default(node) {
    node != null
    node.is_default == true
}
branch_is_default(node) {
    node != null
    node.condition.ir_type == "Null"
}
branch_is_default(node) {
    node != null
    node.condition.ir_type == "Undef"
}
branch_is_default(node) {
    node != null
    node.condition.ir_type == "Boolean"
    node.condition.value == true
}

path_only_else(path) {
    not path_has_non_else(path)
}

path_has_non_else(path) {
    p := path[_]
    p != "else_statement"
}

chain_nodes(top) = nodes {
    nodes := {node |
        walk(top, [path, node])
        node.ir_type == "ConditionalStatement"
        path_only_else(path)
    }
}

chain_has_default(top) {
    nodes := chain_nodes(top)
    node := nodes[_]
    branch_is_default(node)
}

selector_key(expr) = k {
    expr.ir_type == "VariableReference"
    k := sprintf("var:%s", [expr.value])
}
selector_key(expr) = k {
    expr.ir_type != "VariableReference"
    expr.code != ""
    k := sprintf("code:%s", [expr.code])
}
selector_key(expr) = k {
    expr.ir_type != "VariableReference"
    expr.code == ""
    k := sprintf("type:%s", [expr.ir_type])
}

cond_bool_case(cond) = {"selector": sel, "value": val} {
    cond.ir_type == "VariableReference"
    sel := selector_key(cond)
    val := true
}
cond_bool_case(cond) = {"selector": sel, "value": val} {
    cond.ir_type == "Not"
    sel := selector_key(cond.expr)
    val := false
}
cond_bool_case(cond) = {"selector": sel, "value": val} {
    cond.ir_type == "Equal"
    cond.left.ir_type == "Boolean"
    cond.right.ir_type != "Boolean"
    sel := selector_key(cond.right)
    val := cond.left.value
}
cond_bool_case(cond) = {"selector": sel, "value": val} {
    cond.ir_type == "Equal"
    cond.right.ir_type == "Boolean"
    cond.left.ir_type != "Boolean"
    sel := selector_key(cond.left)
    val := cond.right.value
}

bool_exhaustive_chain(top) {
    top != null
    b1 := top
    b2 := top.else_statement
    b2 != null
    b2.else_statement == null
    c1 := cond_bool_case(b1.condition)
    c2 := cond_bool_case(b2.condition)
    c1.selector == c2.selector
    {c1.value, c2.value} == {true, false}
}

has_parent_else(cond, conds) {
    parent := conds[_]
    parent.else_statement == cond
}

is_chain_top(cond, conds) {
    not has_parent_else(cond, conds)
}

is_lookup_function(name) {
    fn := lookup_function_names[_]
    lower(name) == fn
}

is_lookup_method(name) {
    fn := lookup_method_names[_]
    lower(name) == fn
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conds := glitch_lib.all_conditional_statements(parent)
    cond := conds[_]

    is_chain_top(cond, conds)
    cond.else_statement != null
    not chain_has_default(cond)
    not bool_exhaustive_chain(cond)

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in multi-branch selection - Multi-branch conditionals should include a default/catch-all branch. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, call])
    call.ir_type == "FunctionCall"
    is_lookup_function(call.name)
    count(call.args) <= 2

    result := {
        "type": "sec_no_default_switch",
        "element": call,
        "path": parent.path,
        "description": "Missing default case in lookup/mapping - Lookups should include a default/fallback value. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, call])
    call.ir_type == "MethodCall"
    is_lookup_method(call.method)
    count(call.args) <= 1

    result := {
        "type": "sec_no_default_switch",
        "element": call,
        "path": parent.path,
        "description": "Missing default case in lookup/mapping - Lookups should include a default/fallback value. (CWE-478)"
    }
}