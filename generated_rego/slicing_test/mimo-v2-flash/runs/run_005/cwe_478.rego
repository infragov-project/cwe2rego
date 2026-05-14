package glitch

import data.glitch_lib

# Detect missing default branch in switch statements
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "ConditionalStatement"
    node.type == 2
    node.is_top == true

    # Check if any child conditional is marked as default
    has_default := false
    some statement
    statement := node.statements[_]
    statement.ir_type == "ConditionalStatement"
    statement.is_default == true
    has_default := true

    not has_default

    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in switch statement - Switch statement lacks a default case for unhandled values. (CWE-478)"
    }
}

# Detect missing else branch in if statements
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "ConditionalStatement"
    node.type == 1
    node.is_top == true

    # If no else_statement, it's missing the fallback
    not node.else_statement

    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing else branch in if statement - If statement lacks an 'else' branch for unhandled states. (CWE-478)"
    }
}