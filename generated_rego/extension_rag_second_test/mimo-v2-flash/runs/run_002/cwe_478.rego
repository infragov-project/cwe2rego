package glitch

import data.glitch_lib

# Helper function to check if a conditional chain has a default case
has_default_case(cs) {
    cs.is_default == true
} else {
    cs.else_statement != null
    has_default_case(cs.else_statement)
}

Glitch_Analysis[result] {
    # Gather parent unit blocks
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Find conditional statements within this parent
    conditions := glitch_lib.all_conditional_statements(parent)
    cs := conditions[_]

    # We only care about top-level conditional chains
    cs.is_top == true

    # Check if this chain has a default case
    not has_default_case(cs)

    result := {
        "type": "sec_no_default_switch",
        "element": cs,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - This may lead to undefined behavior when an unexpected condition is encountered. (CWE-478)"
    }
}