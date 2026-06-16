package glitch

import data.glitch_lib

collect_conditionals_helper(cond, acc) = result {
    new_acc := acc | {cond}
    cond.else_statement != null
    result := collect_conditionals_helper(cond.else_statement, new_acc)
} else {
    result := acc | {cond}
}

collect_conditionals(cond) = chain {
    chain := collect_conditionals_helper(cond, {})
}

has_default_branch(cond) {
    chain := collect_conditionals(cond)
    defaults := {c | c := chain; c.is_default == true}
    count(defaults) > 0
}

is_multi_branch(cond) {
    cond.type == "SWITCH"
}

is_multi_branch(cond) {
    cond.type == "IF"
    cond.else_statement != null
}

is_else_statement_of_any(c, conditionals) {
    some other
    conditionals[other]
    other.else_statement == c
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    top_conditionals := {c | c := conditionals; not is_else_statement_of_any(c, conditionals)}
    top_cond := top_conditionals[_]
    is_multi_branch(top_cond)
    not has_default_branch(top_cond)
    result := {
        "type": "sec_no_default_switch",
        "element": top_cond,
        "path": parent.path,
        "description": "Missing default case in conditional statement - Unhandled cases may lead to unexpected behavior. (CWE-478)"
    }
}