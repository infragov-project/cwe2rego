package glitch

import data.glitch_lib

switch_chain_has_default(cond) {
    walk(cond, [path, node])
    node.ir_type == "ConditionalStatement"
    node.is_default == true
    count({k | k := path[_]; k != "else_statement"}) == 0
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, cond])
    cond.ir_type == "ConditionalStatement"
    cond.type == "SWITCH"
    cond.is_top == true
    cond.is_default == false
    not cond.condition.right.ir_type == "Boolean"
    not switch_chain_has_default(cond)
    result := {
        "type": "sec_no_default_switch",
        "element": cond.condition.left,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Switch/case statement lacks a default branch, leaving undefined states unhandled when unexpected values are encountered. (CWE-478)"
    }
}