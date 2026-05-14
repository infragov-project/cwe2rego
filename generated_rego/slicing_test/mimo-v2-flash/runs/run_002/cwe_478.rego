package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    # Find all top-level conditional statements
    walk(input, [_, node])
    node.ir_type == "ConditionalStatement"
    node.is_top == true

    # Check if the chain of else statements terminates without a default
    not has_default_in_chain(node)

    # Ensure we are in a valid context (inside a module or script)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Conditional logic checks for specific values but lacks a catch-all handler. (CWE-478)"
    }
}

# Collect the entire chain of else statements as a set
get_else_chain(node) = chain {
    chain := collect_else_nodes(node, [])
}

# Helper function to recursively collect nodes (iterative approach via recursion on list)
collect_else_nodes(current, acc) = result {
    # Base case: no else statement
    not current.else_statement
    result := array.concat(acc, [current])
} else {
    # Recursive step: append current and continue with else
    current.else_statement
    result := collect_else_nodes(current.else_statement, array.concat(acc, [current]))
}

# Check if any node in the chain is marked as default
has_default_in_chain(node) {
    chain := get_else_chain(node)
    count([n | n := chain[_]; n.is_default == true]) > 0
}