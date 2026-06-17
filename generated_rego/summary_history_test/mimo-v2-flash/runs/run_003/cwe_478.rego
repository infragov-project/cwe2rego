package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
    node.is_top == true
    
    # Check if the switch chain has a default case
    not has_default_in_chain(node)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression. (CWE-478)"
    }
}

# Helper rule to check if a switch chain has a default case
has_default_in_chain(node) {
    node.is_default == true
}

has_default_in_chain(node) {
    node.else_statement != null
    node.else_statement.ir_type == "ConditionalStatement"
    node.else_statement.type == "SWITCH"
    has_default_in_chain(node.else_statement)
}