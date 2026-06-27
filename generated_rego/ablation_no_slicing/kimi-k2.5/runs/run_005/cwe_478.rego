package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    
    node.ir_type == "ConditionalStatement"
    node.type == 2
    not node.is_default
    node.is_top == true
    
    not has_default_in_chain(node)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Incomplete conditional logic without default case - Switch statements should include a default/catch-all branch to handle unexpected values. (CWE-478)"
    }
}

has_default_in_chain(node) {
    chain_nodes := [n | 
        some p, n
        walk(node, [p, n])
        n.ir_type == "ConditionalStatement"
    ]
    some chain_node in chain_nodes
    chain_node.is_default
}