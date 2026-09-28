package glitch

import data.glitch_lib

chain_has_direct_default(cond) {
    walk(cond, [path, node])
    node.ir_type == "ConditionalStatement"
    node.is_default == true
    count({p | p := path[_]; p != "else_statement"}) == 0
}

is_boolean_exhaustive(cond) {
    cond.else_statement != null
    cond.else_statement.else_statement == null
    cond.condition.right.ir_type == "Boolean"
    cond.else_statement.condition.right.ir_type == "Boolean"
    cond.condition.right.value != cond.else_statement.condition.right.value
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, cond])
    cond.ir_type == "ConditionalStatement"
    cond.type == "SWITCH"
    cond.is_top == true
    cond.line > 0

    not chain_has_direct_default(cond)
    not is_boolean_exhaustive(cond)

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in conditional statement - Conditional or branching logic does not account for all possible input values. A default or else branch should always be present to avoid unhandled states and potential misconfigurations. (CWE-478)"
    }
}