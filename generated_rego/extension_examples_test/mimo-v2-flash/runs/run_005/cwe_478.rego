package glitch

import data.glitch_lib

# Function to check if a condition chain has a default case (non-recursive)
has_default_in_chain(cond) := true if {
    # Check current condition
    cond.is_default
} else := true if {
    # Check else_statement recursively using walk
    walk(cond, [path, node])
    node.ir_type == "ConditionalStatement"
    node.is_default
} else := false

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    cond := conditionals[_]
    cond.is_top == true
    cond.type == 1  # IF type

    not has_default_in_chain(cond)

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in conditional chain. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    cond := conditionals[_]
    cond.is_top == true
    cond.type == 2  # SWITCH type

    not has_default_in_chain(cond)

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in switch chain. (CWE-478)"
    }
}