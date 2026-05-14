package glitch

import data.glitch_lib

# Helper function to check if a node is inside an AtomicUnit
is_inside_atomic_unit(path) {
    some i
    path[i] == "atomic_units"
}

# Rule for IF conditionals without else branch
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "ConditionalStatement"
    node.type == "IF"
    node.else_statement == null
    not is_inside_atomic_unit(path)
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in conditional expression - Unhandled states can lead to misconfigurations. (CWE-478)"
    }
}

# Rule for SWITCH conditionals without default case - using iterative approach
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
    not is_inside_atomic_unit(path)
    
    # Check the chain of else_statement for a default case without recursion
    has_no_default_case(node)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in conditional expression - Unhandled states can lead to misconfigurations. (CWE-478)"
    }
}

# Iterative check for default case in switch chain (no recursion)
has_no_default_case(node) {
    # If the current node has an else_statement that is a default case, then it has a default
    node.else_statement != null
    node.else_statement.is_default == true
    false
} else {
    # If the current node has an else_statement that is another switch, check that switch
    node.else_statement != null
    node.else_statement.type == "SWITCH"
    # We need to check the else_statement of the else_statement
    # But without recursion, we'll use a fixed depth approach
    not has_default_at_depth(node.else_statement, 1)
} else {
    # If there's no else_statement at all, then it has no default
    node.else_statement == null
    true
}

# Helper to check for default at a specific depth (iterative approach)
has_default_at_depth(current_node, depth) {
    # Base case: check current node
    current_node.else_statement != null
    current_node.else_statement.is_default == true
} else {
    # If we haven't reached max depth and there's another switch
    depth < 5  # Limit depth to avoid infinite loops
    current_node.else_statement != null
    current_node.else_statement.type == "SWITCH"
    # Recursively check next level (but without actual recursion using depth limit)
    has_default_at_depth(current_node.else_statement, depth + 1)
}