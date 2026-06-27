package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    
    cond.type == 2
    cond.is_top == true
    at_least_n_branches(cond, 2)
    not has_default_in_switch(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing Default Case in Multiple Condition Expression - Multi-branch switch/case statement lacks a default/catch-all fallback mechanism. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    
    cond.type == 1
    cond.is_top == true
    at_least_n_branches(cond, 2)
    not has_final_else(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing Default Case in Multiple Condition Expression - If-elif chain lacks a final else fallback. (CWE-478)"
    }
}

at_least_n_branches(cond, n) {
    count_branches(cond) >= n
}

count_branches(cond) = c {
    pairs := [[path, val] | walk(cond, [path, val])]
    filtered := {pair | pair := pairs[_]; is_non_default_switch_branch(pair[1])}
    c := count(filtered)
}

is_non_default_switch_branch(val) {
    val.ir_type == "ConditionalStatement"
    val.type == 2
    not is_default_marker(val)
}

is_default_marker(val) {
    val.is_default == true
}

is_default_marker(val) {
    val.condition.ir_type == "Null"
}

is_default_marker(val) {
    val.condition == null
}

has_default_in_switch(cond) {
    walk(cond, [_, val])
    val.ir_type == "ConditionalStatement"
    is_default_marker(val)
}

has_final_else(cond) {
    last := find_terminal(cond)
    last != null
    last.ir_type == "ConditionalStatement"
    is_default_marker(last)
}

find_terminal(cond) = result {
    walk(cond, [_, end])
    is_terminal_node(end, cond)
    result := end
}

find_terminal(_) = null

is_terminal_node(node, root) {
    node.ir_type == "ConditionalStatement"
    node.else_statement == null
    is_in_chain(node, root)
}

is_in_chain(node, root) {
    root.else_statement == node
}

is_in_chain(node, root) {
    intermediate := root.else_statement
    intermediate.ir_type == "ConditionalStatement"
    is_in_chain(node, intermediate)
}