package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Identify conditional statements
    walk(parent, [_, cond])
    cond.ir_type == "ConditionalStatement"
    cond.is_top == true
    
    # Condition 1: Detect missing default in SWITCH statements
    cond.type == "SWITCH"
    not has_default_case(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in switch-like conditional logic - The conditional statement handles specific enumerated values but fails to account for all other possible inputs via a default case, leading to CWE-478."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Identify conditional statements
    walk(parent, [_, cond])
    cond.ir_type == "ConditionalStatement"
    cond.is_top == true
    
    # Condition 2: Detect incomplete IF/ELSE chains (missing terminal else)
    cond.type == "IF"
    has_discrete_check(cond.condition)
    not cond.else_statement
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing else branch in conditional logic - The if/elif chain handles specific enumerated values but lacks a terminal else branch for all other possible inputs, leading to CWE-478."
    }
}

# Helper to check if a conditional has a default case
has_default_case(cond) {
    walk(cond, [path, node])
    node.ir_type == "ConditionalStatement"
    node.is_default == true
}

# Helper to check if a condition involves discrete value checks
has_discrete_check(condition) {
    walk(condition, [_, node])
    node.ir_type == "Equal"
    node.left.ir_type == "VariableReference"
    node.right.ir_type == "String"
} else {
    walk(condition, [_, node])
    node.ir_type == "Equal"
    node.left.ir_type == "VariableReference"
    node.right.ir_type == "Integer"
} else {
    walk(condition, [_, node])
    node.ir_type == "Equal"
    node.left.ir_type == "VariableReference"
    node.right.ir_type == "AddArgs"
}