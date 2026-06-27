package glitch

import data.glitch_lib

# Helper: Check if type is SWITCH
is_switch_type(type) {
    type == "SWITCH"
} else {
    type == 2
}

# Helper: Build chain of else_statement linked nodes using comprehension with union
# We build up to 5 levels deep without recursion
build_chain(node) = chain {
    level0 := {n | n := node}
    level1 := {n | node.else_statement != null; n := node.else_statement}
    level2 := {n | node.else_statement != null; node.else_statement.else_statement != null; n := node.else_statement.else_statement}
    level3 := {n | node.else_statement != null; node.else_statement.else_statement != null; node.else_statement.else_statement.else_statement != null; n := node.else_statement.else_statement.else_statement}
    level4 := {n | node.else_statement != null; node.else_statement.else_statement != null; node.else_statement.else_statement.else_statement != null; node.else_statement.else_statement.else_statement.else_statement != null; n := node.else_statement.else_statement.else_statement.else_statement}
    level5 := {n | node.else_statement != null; node.else_statement.else_statement != null; node.else_statement.else_statement.else_statement != null; node.else_statement.else_statement.else_statement.else_statement != null; node.else_statement.else_statement.else_statement.else_statement.else_statement != null; n := node.else_statement.else_statement.else_statement.else_statement.else_statement}
    chain := level0 | level1 | level2 | level3 | level4 | level5
}

# Helper: Check if any node in chain has default
chain_has_default(node) {
    chain := build_chain(node)
    chain[c]
    c.is_default == true
}

# Collect all switch conditional statements from a unit block
all_switch_conditionals(unit) = switches {
    switches := {n |
        walk(unit, [path, n])
        n.ir_type == "ConditionalStatement"
        is_switch_type(n.type)
    }
}

# Main rule: Detect SWITCH statements without default branch
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_switches := all_switch_conditionals(parent)
    node := all_switches[_]
    
    not chain_has_default(node)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing Default Case in Multiple Condition Expression - Switch-like conditional lacks a default/fallback branch to handle unanticipated states. (CWE-478)"
    }
}