package glitch

import data.glitch_lib

path_through_statements(path) {
    path[_] == "statements"
}

chain_has_default(cond) {
    walk(cond, [path, node])
    node.ir_type == "ConditionalStatement"
    node.is_default == true
    not path_through_statements(path)
}

is_boolean_exhaustive(cond) {
    walk(cond, [path1, n1])
    n1.ir_type == "ConditionalStatement"
    not path_through_statements(path1)
    n1.condition.right.ir_type == "Boolean"
    n1.condition.right.value == true
    walk(cond, [path2, n2])
    n2.ir_type == "ConditionalStatement"
    not path_through_statements(path2)
    n2.condition.right.ir_type == "Boolean"
    n2.condition.right.value == false
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]

    cond.type == "SWITCH"
    cond.is_top == true
    cond.else_statement != null
    not chain_has_default(cond)
    not is_boolean_exhaustive(cond)

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Multi-branch conditional lacks a default/else fallback, leaving unmatched states unhandled. (CWE-478)"
    }
}