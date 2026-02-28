package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    top_cond := conditionals[_]
    top_cond.is_top == true
    
    # Collect all nodes in the chain without recursion
    chain_nodes := [n |
        # Start with the top conditional
        n := top_cond
    ]
    
    # Continue adding else_statements until we hit null
    chain_nodes_2 := [n |
        n := chain_nodes[_]
    ]
    
    # Alternative approach: use walk and filter by path structure
    walk_nodes := {n |
        walk(top_cond, [path, n])
        n.ir_type == "ConditionalStatement"
        # Check if path only contains "else_statement" (for the chain) or is empty (for top_cond)
        # Count the number of path elements that are "else_statement"
        else_count := count([i | path[i] == "else_statement"])
        # Allow if the entire path is either empty or all elements are "else_statement"
        total_len := count(path)
        total_len == else_count
    }
    
    # Check if none of the nodes in the chain have is_default == true
    not has_default_in_set(walk_nodes)
    
    result := {
        "type": "sec_no_default_switch",
        "element": top_cond,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression. (CWE-478)"
    }
}

has_default_in_set(nodes) {
    node := nodes[_]
    node.is_default == true
}