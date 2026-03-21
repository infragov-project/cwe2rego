package glitch

import data.glitch_lib

conditional_chain_has_default(cs) {
    walk(cs, [path, n])
    n.ir_type == "ConditionalStatement"
    n.is_default == true
    not path_goes_through_statements(path)
}

path_goes_through_statements(path) {
    path[_] == "statements"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, cs])
    cs.ir_type == "ConditionalStatement"
    cs.is_top == true
    cs.else_statement != null
    not conditional_chain_has_default(cs)
    result := {
        "type": "sec_no_default_switch",
        "element": cs,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Conditional chain lacks a default/else branch to handle unmatched values. (CWE-478)"
    }
}