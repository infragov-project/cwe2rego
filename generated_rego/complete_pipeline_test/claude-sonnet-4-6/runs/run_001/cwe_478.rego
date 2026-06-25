package glitch

import data.glitch_lib

bad_path_element(path) {
    elem := path[_]
    is_string(elem)
    elem != "else_statement"
}

direct_chain_has_default(cond) {
    walk(cond, [path, node])
    node.ir_type == "ConditionalStatement"
    node.is_default == true
    not bad_path_element(path)
}

direct_chain_covers_bool(cond, val) {
    walk(cond, [path, node])
    node.ir_type == "ConditionalStatement"
    node.condition.right.ir_type == "Boolean"
    node.condition.right.value == val
    not bad_path_element(path)
}

is_boolean_exhaustive(cond) {
    direct_chain_covers_bool(cond, true)
    direct_chain_covers_bool(cond, false)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, cond])
    cond.ir_type == "ConditionalStatement"
    cond.is_top == true
    cond.type == "SWITCH"
    not direct_chain_has_default(cond)
    not is_boolean_exhaustive(cond)

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in switch/multi-condition expression - All switch expressions should include a default/fallback case. (CWE-478)"
    }
}