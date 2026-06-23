package glitch

import data.glitch_lib
import future.keywords.in
import future.keywords.every

# Collect all ConditionalStatement nodes from UnitBlocks with valid paths
all_conditionals[cond] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, cond])
    cond.ir_type == "ConditionalStatement"
    cond.type == "SWITCH"
}

# Check for dynamic/external input sources in condition
has_dynamic_condition_source(cond) {
    cond.condition != null
    walk(cond.condition, [_, node])
    node.ir_type == "VariableReference"
}

has_dynamic_condition_source(cond) {
    cond.condition != null
    walk(cond.condition, [_, node])
    node.ir_type == "Access"
}

has_dynamic_condition_source(cond) {
    cond.condition != null
    walk(cond.condition, [_, node])
    node.ir_type == "MethodCall"
}

has_dynamic_condition_source(cond) {
    cond.condition != null
    walk(cond.condition, [_, node])
    node.ir_type == "FunctionCall"
}

# Find all nodes in the else chain of a SWITCH - only follow SWITCH type nodes
# This ensures we don't get confused by nested IF statements inside SWITCH branches
chain_nodes(cond) = nodes {
    # Level 0: the SWITCH node itself
    l0 := {cond}
    
    # Level 1: else_statement if it's also a SWITCH
    l1 := {n |
        some c in l0
        c.else_statement != null
        n := c.else_statement
        n.ir_type == "ConditionalStatement"
        n.type == "SWITCH"
    }
    
    # Level 2
    l2 := {n |
        some c in l1
        c.else_statement != null
        n := c.else_statement
        n.ir_type == "ConditionalStatement"
        n.type == "SWITCH"
    }
    
    # Level 3
    l3 := {n |
        some c in l2
        c.else_statement != null
        n := c.else_statement
        n.ir_type == "ConditionalStatement"
        n.type == "SWITCH"
    }
    
    # Level 4
    l4 := {n |
        some c in l3
        c.else_statement != null
        n := c.else_statement
        n.ir_type == "ConditionalStatement"
        n.type == "SWITCH"
    }
    
    # Level 5
    l5 := {n |
        some c in l4
        c.else_statement != null
        n := c.else_statement
        n.ir_type == "ConditionalStatement"
        n.type == "SWITCH"
    }
    
    # Level 6
    l6 := {n |
        some c in l5
        c.else_statement != null
        n := c.else_statement
        n.ir_type == "ConditionalStatement"
        n.type == "SWITCH"
    }
    
    # Level 7
    l7 := {n |
        some c in l6
        c.else_statement != null
        n := c.else_statement
        n.ir_type == "ConditionalStatement"
        n.type == "SWITCH"
    }
    
    # Level 8
    l8 := {n |
        some c in l7
        c.else_statement != null
        n := c.else_statement
        n.ir_type == "ConditionalStatement"
        n.type == "SWITCH"
    }
    
    # Level 9
    l9 := {n |
        some c in l8
        c.else_statement != null
        n := c.else_statement
        n.ir_type == "ConditionalStatement"
        n.type == "SWITCH"
    }
    
    # Level 10
    l10 := {n |
        some c in l9
        c.else_statement != null
        n := c.else_statement
        n.ir_type == "ConditionalStatement"
        n.type == "SWITCH"
    }
    
    nodes := l0 | l1 | l2 | l3 | l4 | l5 | l6 | l7 | l8 | l9 | l10
}

# Check if any SWITCH node in the chain has is_default = true
chain_has_default(cond) {
    some node in chain_nodes(cond)
    node.is_default == true
}

# Get the containing UnitBlock path for a conditional
get_path(cond) = path {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node == cond
    path := parent.path
}

# Check if the SWITCH condition compares against a variable that drives multiple branches
# This is the key pattern: a SWITCH where the condition is an external input
has_switch_condition_pattern(cond) {
    # The condition should be comparing a variable against literal values
    cond.condition != null
    cond.condition.ir_type == "Equal"
    walk(cond.condition.left, [_, node])
    node.ir_type == "VariableReference"
}

has_switch_condition_pattern(cond) {
    cond.condition != null
    cond.condition.ir_type == "Equal"
    walk(cond.condition.left, [_, node])
    node.ir_type == "Access"
}

has_switch_condition_pattern(cond) {
    cond.condition != null
    cond.condition.ir_type == "Equal"
    walk(cond.condition.left, [_, node])
    node.ir_type == "MethodCall"
}

has_switch_condition_pattern(cond) {
    cond.condition != null
    cond.condition.ir_type == "Equal"
    walk(cond.condition.left, [_, node])
    node.ir_type == "FunctionCall"
}

# Main detection: missing default in SWITCH statements with dynamic conditions
Glitch_Analysis[result] {
    cond := all_conditionals[_]
    
    # Must have dynamic input driving the condition
    has_dynamic_condition_source(cond)
    
    # Must follow the SWITCH pattern (comparing variable against values)
    has_switch_condition_pattern(cond)
    
    # Must NOT have a default anywhere in the SWITCH chain
    not chain_has_default(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": get_path(cond),
        "description": "Missing default case in switch statement - Switch statements with variable-driven conditions should have a default case to handle unexpected values. (CWE-478)"
    }
}