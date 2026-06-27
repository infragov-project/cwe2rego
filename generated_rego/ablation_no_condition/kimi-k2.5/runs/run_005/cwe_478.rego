package glitch

import data.glitch_lib
import future.keywords.in

# Check if a switch is used as a value in a Variable (selector expression)
is_selector_expression(node) {
    walk(input, [path, value])
    value.ir_type == "Variable"
    value.value == node
}

# Check if a switch is exhaustively typed (boolean true/false only)
is_boolean_exhaustive(node) {
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
    
    # Collect all conditions in the chain
    conditions := {c | 
        walk(node, [_, n])
        n.ir_type == "ConditionalStatement"
        n.type == "SWITCH"
        c := n.condition
    }
    
    # Check if all conditions are boolean comparisons
    every cond in conditions {
        cond.ir_type == "Equal"
        cond.right.ir_type in {"Boolean", "True", "False"}
    }
    
    # Count boolean cases - should be exactly 2 for true/false
    count(conditions) == 2
}

# Check if any node in the chain has is_default == true
has_default_in_chain(node) {
    walk(node, [_, n])
    n.ir_type == "ConditionalStatement"
    n.type == "SWITCH"
    n.is_default == true
}

# Gather all UnitBlocks from anywhere in the input
all_unit_blocks[ub] {
    walk(input, [_, ub])
    ub.ir_type == "UnitBlock"
}

# Find path for a node by walking up to find enclosing UnitBlock with path
get_path_for_node(node) = path {
    walk(input, [node_path, _])
    some i in numbers.range(0, count(node_path))
    prefix := array.slice(node_path, 0, i)
    ancestor := object.get(input, prefix, null)
    ancestor.ir_type == "UnitBlock"
    ancestor.path != ""
    path := ancestor.path
}

# Find all switch entry nodes (is_top == true) under a root
find_switch_entries(root) = switches {
    switches := {n | 
        walk(root, [_, n])
        n.ir_type == "ConditionalStatement"
        n.type == "SWITCH"
        n.is_top == true
    }
}

# Main analysis
Glitch_Analysis[result] {
    # Gather from all UnitBlocks
    ub := all_unit_blocks[_]
    
    # Find all switch entries
    entries := find_switch_entries(ub)
    entry := entries[_]
    
    # Skip selector expressions (used as values)
    not is_selector_expression(entry)
    
    # Skip boolean exhaustive switches
    not is_boolean_exhaustive(entry)
    
    # Must NOT have a default case in chain
    not has_default_in_chain(entry)
    
    # Get path for reporting
    path := get_path_for_node(entry)
    
    result := {
        "type": "sec_no_default_switch",
        "element": entry,
        "path": path,
        "description": "Missing default case in multiple condition expression - Switch statements should have a default case to handle unexpected values. (CWE-478)"
    }
}