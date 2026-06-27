package glitch

import data.glitch_lib

import future.keywords.in

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
    
    not switch_has_default(node)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Ensure that switch statements have a default case to handle unexpected values. (CWE-478)"
    }
}

switch_has_default(switch_stmt) {
    switch_stmt.is_default == true
}

switch_has_default(switch_stmt) {
    some chain_node in else_chain_nodes(switch_stmt)
    chain_node.is_default == true
}

else_chain_nodes(start) := nodes {
    nodes := walk_chain(start)
}

walk_chain(current) := {n | 
    some n in chain_set(current)
}

chain_set(start) := result {
    result := {node |
        [path, node] := walk(start)
        node.ir_type == "ConditionalStatement"
    }
}