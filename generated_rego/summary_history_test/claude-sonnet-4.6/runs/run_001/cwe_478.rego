package glitch

import data.glitch_lib

path_has_non_else_key(path) {
    p := path[_]
    is_string(p)
    p != "else_statement"
}

chain_has_default(cond) {
    walk(cond, [path, node])
    node.ir_type == "ConditionalStatement"
    node.is_default == true
    not path_has_non_else_key(path)
}

chain_has_non_boolean_condition(cond) {
    walk(cond, [path, node])
    not path_has_non_else_key(path)
    node.ir_type == "ConditionalStatement"
    node.condition.ir_type == "Equal"
    not node.condition.right.ir_type == "Boolean"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conds := glitch_lib.all_conditional_statements(parent)
    cond := conds[_]
    cond.is_top == true
    cond.type == "SWITCH"
    cond.else_statement != null
    not chain_has_default(cond)
    chain_has_non_boolean_condition(cond)
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - conditional chains should have a default/else branch to handle unexpected values. (CWE-478)"
    }
}