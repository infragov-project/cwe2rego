package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conditions := glitch_lib.all_conditional_statements(parent)
    node := conditions[_]
    
    node.type == "SWITCH"
    not node.is_default
    
    count_switch_cases(node) > 0
    not has_default_branch(node)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in switch statement - Switch statements should include a default case to handle unexpected values. (CWE-478)"
    }
}

count_switch_cases(node) = n {
    n := count([c | walk(node, [_, c]); c.ir_type == "ConditionalStatement"; c.type == "SWITCH"])
}

has_default_branch(node) {
    walk(node, [_, c])
    c.ir_type == "ConditionalStatement"
    c.is_default == true
}