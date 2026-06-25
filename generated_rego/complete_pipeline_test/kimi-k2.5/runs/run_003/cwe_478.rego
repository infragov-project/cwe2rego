package glitch

import data.glitch_lib
import future.keywords.in

is_switch_type(node) {
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
}

collect_switch_chain(switch_node) = chain {
    is_switch_type(switch_node)
    chain := [n | walk(switch_node, [[_], n]); is_switch_type(n)]
}

chain_has_default(chain) {
    some node in chain
    node.is_default == true
}

switch_chain_ends_without_default(switch_node) {
    is_switch_type(switch_node)
    switch_node.is_top == true
    chain := collect_switch_chain(switch_node)
    not chain_has_default(chain)
}

is_exhaustive_boolean_switch(switch_node) {
    chain := collect_switch_chain(switch_node)
    condition_values := {v | 
        some node in chain
        node.condition.ir_type == "Equal"
        node.condition.right.ir_type == "Boolean"
        v := node.condition.right.value
    }
    
    condition_values[true]
    condition_values[false]
    count(condition_values) == 2
}

switch_missing_default(switch_node) {
    switch_chain_ends_without_default(switch_node)
    not is_exhaustive_boolean_switch(switch_node)
}

lookup_without_default(node) {
    node.ir_type == "FunctionCall"
    lower(node.name) == "lookup"
    count(node.args) < 3
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [[_], node])
    is_switch_type(node)
    node.is_top == true
    switch_missing_default(node)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Switch/case statements should include a default case to handle unanticipated values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [[_], node])
    lookup_without_default(node)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in lookup function - lookup() should include a default value to handle missing keys. (CWE-478)"
    }
}