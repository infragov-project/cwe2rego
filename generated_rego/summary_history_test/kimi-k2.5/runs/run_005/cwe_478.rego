package glitch

import data.glitch_lib

valid_line(node) {
    node.line > 0
    node.line < 100000
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
    node.is_top == true
    
    valid_line(node)
    
    not has_any_default(node)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in switch statement - Switch-style conditional lacks a default case to handle unexpected values, which may lead to unpredictable behavior or security issues. (CWE-478)"
    }
}

has_any_default(node) {
    node.is_default == true
} else {
    node.else_statement.is_default == true
} else {
    node.else_statement != null
    has_any_default(node.else_statement)
}