package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]
    conditional.type == "ConditionalStatement"
    conditional.is_top == true

    has_default := false
    walk(conditional, [path, node])
    node.ir_type == "ConditionalStatement"
    node.is_default == true
    has_default := true

    not has_default

    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Missing default case in conditional expression - Conditional logic lacks a fallback branch to handle unexpected values. (CWE-478)"
    }
}