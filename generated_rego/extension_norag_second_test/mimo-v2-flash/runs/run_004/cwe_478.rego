package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, node])
    node.ir_type == "ConditionalStatement"
    node.is_top == true
    not node.is_default

    has_var_ref(node.condition)

    chain_conditions := collect_conditions(node)

    non_default_count := count([c | c := chain_conditions[_]; not c.is_default])
    non_default_count > 0

    default_count := count([c | c := chain_conditions[_]; c.is_default])
    default_count == 0

    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in conditional logic - Conditional statement lacks a default branch to handle unexpected values, which can lead to undefined behavior. (CWE-478)"
    }
}

collect_conditions(node) = chain {
    chain := [n | some n; n = walk_condition_chain(node)[_]]
}

walk_condition_chain(start) = chain {
    chain := _walk_chain(start, [])
}

_walk_chain(current, acc) = chain {
    current.ir_type != "ConditionalStatement"
    chain := acc
}

_walk_chain(current, acc) = chain {
    current.ir_type == "ConditionalStatement"
    new_acc := array.concat(acc, [current])
    current.else_statement
    chain := _walk_chain(current.else_statement, new_acc)
}

_walk_chain(current, acc) = chain {
    current.ir_type == "ConditionalStatement"
    not current.else_statement
    chain := array.concat(acc, [current])
}

has_var_ref(node) {
    walk(node, [_, n])
    n.ir_type == "VariableReference"
}