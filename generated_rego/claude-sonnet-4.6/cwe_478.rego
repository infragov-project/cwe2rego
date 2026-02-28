package glitch

import data.glitch_lib

# Check if a conditional chain contains a default/catch-all branch
conditional_has_default(cond) {
    walk(cond, [_, n])
    n.ir_type == "ConditionalStatement"
    n.is_default == true
}

# Detect: Multi-branch if/elif or switch/case chains without a default/else/catch-all case (CWE-478)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]

    # Only evaluate the top of a conditional chain (not nested elif/else branches)
    cond.is_top == true

    # Must have at least one subsequent branch (else_statement present and is a ConditionalStatement)
    # This ensures we only flag multi-branch constructs, not simple standalone if statements
    cond.else_statement.ir_type == "ConditionalStatement"

    # No branch in the chain is marked as default/catch-all
    not conditional_has_default(cond)

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing Default Case in Multiple Condition Expression - Multi-branch conditional construct lacks a default or catch-all case (else/default/otherwise). (CWE-478)"
    }
}