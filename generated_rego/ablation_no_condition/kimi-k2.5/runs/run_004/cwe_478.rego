package glitch

import data.glitch_lib

is_switch(node) {
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
}

# Collect nodes in the else_statement chain, only following linked conditionals
else_chain_nodes(node) = chain {
    chain := {n |
        walk(node, [path, n])
        n.ir_type == "ConditionalStatement"
        is_in_else_chain(path, node)
    }
}

# Check if a node at given path is in the else_statement chain from the start node
is_in_else_chain(path, start_node) {
    # Direct child of else_statement from start or its chain
    path[0] == "else_statement"
} else {
    # Nested in statements of a node in the chain
    some parent_path
    parent_path = array.slice(path, 0, count(path) - 1)
    parent_path[0] == "else_statement"
}

# Check if switch has default case anywhere in its chain
switch_has_default(node) {
    node.is_default == true
} else {
    node.else_statement != null
    switch_has_default(node.else_statement)
}

# Check if this is a boolean exhaustive switch (true/false only cases)
is_boolean_exhaustive_switch(node) {
    # Check if all cases are boolean values that cover true and false
    cases := collect_case_values(node)
    cases == {"true", "false"}
}

# Collect all case value strings from a switch and its chain
collect_case_values(node) = values {
    values := {v |
        some n
        n := else_chain_nodes(node)[_]
        v := get_condition_value(n.condition)
        v != null
    }
}

# Try to extract a string representation of condition value
get_condition_value(cond) = val {
    cond.ir_type == "Equal"
    cond.right.ir_type == "Boolean"
    val := cond.right.code
} else = val {
    cond.ir_type == "Equal"
    cond.right.ir_type == "String"
    val := cond.right.value
} else = val {
    cond.ir_type == "Equal"
    is_numeric_literal(cond.right)
    val := cond.right.code
} else = null

is_numeric_literal(node) {
    node.ir_type == "Integer"
} else {
    node.ir_type == "Float"
} else {
    node.ir_type == "Minus"
    node.expr.ir_type == "Integer"
}

# A switch is considered covered if it has a default or is boolean exhaustive
switch_is_covered(node) {
    switch_has_default(node)
} else {
    is_boolean_exhaustive_switch(node)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Find all switch statements in this parent by walking everything
    some node
    walk(parent, [_, node])
    is_switch(node)
    node.is_top == true
    
    # Check if switch is missing coverage (no default and not boolean exhaustive)
    not switch_is_covered(node)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in switch statement - Switch statements should have a default case to handle unexpected values and prevent cascading failures. (CWE-478)"
    }
}