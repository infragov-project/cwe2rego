package glitch

import data.glitch_lib

literal_types = {"String", "Boolean", "Integer", "Null", "Undef"}

has_variable_reference(expr) {
    walk(expr, [_, n])
    n.ir_type == "VariableReference"
}

# Check if a value is a literal type
is_literal_ir_type(t) {
    t == "String"
} else {
    t == "Boolean"
} else {
    t == "Integer"
} else {
    t == "Null"
} else {
    t == "Undef"
}

# Extract all literal values matched in a conditional chain
extract_matched_values(cs) = values {
    values := {v |
        walk(cs, [_, node])
        node.ir_type == "ConditionalStatement"
        node.condition.ir_type == "Equal"
        is_literal_ir_type(node.condition.right.ir_type)
        v := node.condition.right.value
    }
}

# Get the type of the condition subject for type-based exhaustiveness checking
get_condition_subject_type(cs) = t {
    cs.condition.ir_type == "Equal"
    cs.condition.left.ir_type == "VariableReference"
    t := "variable"
} else = t {
    cs.condition.ir_type == "Equal"
    walk(cs.condition.left, [_, n])
    n.ir_type == "VariableReference"
    t := "complex"
} else = t {
    t := "other"
}

# Check if matched values cover all possible values of boolean type
is_boolean_exhaustive(cs) {
    matched := extract_matched_values(cs)
    matched == {true, false}
}

# Check if the condition is comparing against a boolean variable
is_boolean_comparison(cs) {
    cs.condition.ir_type == "Equal"
    cs.condition.right.ir_type == "Boolean"
} else {
    walk(cs, [_, node])
    node.ir_type == "ConditionalStatement"
    node.condition.ir_type == "Equal"
    node.condition.right.ir_type == "Boolean"
}

# Depth-limited chain traversal to find terminal
has_terminal_default(cs) {
    cs.is_default == true
} else {
    cs.else_statement.ir_type == "ConditionalStatement"
    cs.else_statement.is_default == true
} else {
    cs.else_statement.ir_type == "ConditionalStatement"
    cs.else_statement.else_statement.ir_type == "ConditionalStatement"
    cs.else_statement.else_statement.is_default == true
} else {
    cs.else_statement.ir_type == "ConditionalStatement"
    cs.else_statement.else_statement.ir_type == "ConditionalStatement"
    cs.else_statement.else_statement.else_statement.ir_type == "ConditionalStatement"
    cs.else_statement.else_statement.else_statement.is_default == true
} else {
    cs.else_statement.ir_type == "ConditionalStatement"
    cs.else_statement.else_statement.ir_type == "ConditionalStatement"
    cs.else_statement.else_statement.else_statement.ir_type == "ConditionalStatement"
    cs.else_statement.else_statement.else_statement.else_statement.ir_type == "ConditionalStatement"
    cs.else_statement.else_statement.else_statement.else_statement.is_default == true
}

# Check if this is a top-level switch with variable-based condition
is_input_derived_switch(cs) {
    cs.type == "SWITCH"
    cs.is_top == true
    has_variable_reference(cs.condition)
}

# Determine if the switch is exhaustively covered without explicit default
is_exhaustive_without_default(cs) {
    is_boolean_comparison(cs)
    is_boolean_exhaustive(cs)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, cs])
    cs.ir_type == "ConditionalStatement"
    
    is_input_derived_switch(cs)
    not has_terminal_default(cs)
    not is_exhaustive_without_default(cs)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cs,
        "path": parent.path,
        "description": "Missing default case in conditional expression - Switch/case statements should include a default branch to handle unexpected input values. (CWE-478)"
    }
}