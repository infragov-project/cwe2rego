package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditional_statements := glitch_lib.all_conditional_statements(parent)
    node := conditional_statements[_]

    node.is_default == false
    node.else_statement == null
    node.type in {1, 2}

    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default handling in conditional logic (CWE-478)"
    }
}