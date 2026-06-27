package glitch

import data.glitch_lib
import future.keywords.in

default has_default_in_chain := false

has_default_in_chain[node] {
    node.ir_type == "ConditionalStatement"
    node.is_default == true
}

has_default_in_chain[node] {
    node.ir_type == "ConditionalStatement"
    node.else_statement != null
    has_default_in_chain[node.else_statement]
}

get_switch_chain_start[root] {
    walk(input, [_, node])
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
    node.is_top == true
    root := node
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
    node.is_top == true
    
    not has_default_in_chain[node]
    not is_exhaustive_boolean_switch(node)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Switch statements should have a default case to handle unexpected values. (CWE-478)"
    }
}

is_exhaustive_boolean_switch(node) {
    found_true := {1 | walk(node, [_, n]); n.ir_type == "ConditionalStatement"; n.condition != null; is_true_literal(n.condition)}
    found_false := {1 | walk(node, [_, n]); n.ir_type == "ConditionalStatement"; n.condition != null; is_false_literal(n.condition)}
    count(found_true) > 0
    count(found_false) > 0
}

is_true_literal(cond) {
    cond.ir_type == "Boolean"
    cond.value == true
}

is_true_literal(cond) {
    cond.ir_type == "Equal"
    cond.right.ir_type == "Boolean"
    cond.right.value == true
}

is_false_literal(cond) {
    cond.ir_type == "Boolean"
    cond.value == false
}

is_false_literal(cond) {
    cond.ir_type == "Equal"
    cond.right.ir_type == "Boolean"
    cond.right.value == false
}