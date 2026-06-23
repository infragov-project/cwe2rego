package glitch

import data.glitch_lib
import future.keywords.in

external_input_types := {"VariableReference", "FunctionCall", "MethodCall"}

condition_has_external_input(cond) {
    cond.condition != null
    walk(cond.condition, [_, node])
    external_input_types[node.ir_type]
}

# Collect all branches by following else_statement chain directly
collect_else_chain(cond) = chain {
    chain := {node |
        node := _follow_else_chain(cond, _)
    }
}

_follow_else_chain(start, 0) = start

_follow_else_chain(start, n) = result {
    n > 0
    prev := _follow_else_chain(start, n - 1)
    prev.else_statement != null
    result := prev.else_statement
}

count_branches(cond) = n {
    n := count(collect_else_chain(cond))
}

has_default_branch(cond) {
    some b in collect_else_chain(cond)
    b.is_default == true
}

is_exhaustive_versioncmp(cond) {
    count_branches(cond) >= 3
    some b in collect_else_chain(cond)
    b.condition.ir_type == "Equal"
    b.condition.left.ir_type == "FunctionCall"
    lower(b.condition.left.name) == "versioncmp"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    [_, cond] := walk(parent)
    cond.ir_type == "ConditionalStatement"
    cond.type == "SWITCH"
    
    count_branches(cond) >= 2
    condition_has_external_input(cond)
    not has_default_branch(cond)
    not is_exhaustive_versioncmp(cond)

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in switch statement with external input selector - Unhandled cases may lead to undefined behavior and security misconfigurations. (CWE-478)"
    }
}