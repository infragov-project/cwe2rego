package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [path, node])
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"

    is_control_flow_switch(parent, path, node)

    chain := collect_switch_chain(node)
    count(chain) >= 2

    not has_default_in_chain(node)

    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in switch statement - Switch statements should have a default case to handle unexpected values. (CWE-478)"
    }
}

is_control_flow_switch(parent, path, node) {
    node.is_top == true
    is_direct_statement(path)
}

is_control_flow_switch(parent, path, node) {
    not node.is_top
    is_nested_in_control_flow(node)
}

is_direct_statement(path) {
    count(path) == 0
}

is_direct_statement(path) {
    path[count(path) - 1] == "statements"
}

is_nested_in_control_flow(node) {
    walk(node, [_, child])
    child.ir_type == "ConditionalStatement"
    child.is_top == true
}

collect_switch_chain(start) = chain {
    chain := {n |
        walk(start, [path, n])
        n.ir_type == "ConditionalStatement"
        is_else_chain_path_with_depth(path, 10)
    }
}

is_else_chain_path_with_depth(path, depth) {
    depth > 0
    count(path) == 0
}

is_else_chain_path_with_depth(path, depth) {
    depth > 0
    count(path) > 0
    path[0] == "else_statement"
    rest := array.slice(path, 1, count(path))
    is_else_chain_path_helper(rest, depth - 1)
}

is_else_chain_path_helper(path, depth) {
    depth > 0
    count(path) == 0
}

is_else_chain_path_helper(path, depth) {
    depth > 0
    count(path) > 0
    path[0] == "else_statement"
    rest := array.slice(path, 1, count(path))
    is_else_chain_path_helper(rest, depth - 1)
}

has_default_in_chain(node) {
    check_default_with_depth(node, 10)
}

check_default_with_depth(node, depth) {
    depth > 0
    node.is_default == true
}

check_default_with_depth(node, depth) {
    depth > 0
    node.else_statement
    node.else_statement.ir_type == "ConditionalStatement"
    check_default_with_depth(node.else_statement, depth - 1)
}