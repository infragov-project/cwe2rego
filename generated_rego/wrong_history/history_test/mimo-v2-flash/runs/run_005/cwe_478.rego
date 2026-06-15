package glitch

import data.glitch_lib

chain_nodes(cs, node) {
    node == cs
}

chain_nodes(cs, node) {
    cs.else_statement != null
    chain_nodes(cs.else_statement, node)
}

has_default_in_chain(cs) {
    some node
    chain_nodes(cs, node)
    node.is_default == true
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
    node.is_top == true
    not has_default_in_chain(node)
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in conditional logic - Switch statements should have a default case to handle unexpected inputs. (CWE-478)"
    }
}