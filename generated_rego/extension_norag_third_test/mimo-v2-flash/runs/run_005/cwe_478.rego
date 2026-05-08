package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    walk(input, [_, node])
    node.ir_type == "ConditionalStatement"
    node.is_top == true
    node.type == 1
    node.else_statement == null
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": get_path(node),
        "description": "Missing default case in conditional expression - Logic may fail on unexpected values (CWE-478)"
    }
}

Glitch_Analysis[result] {
    walk(input, [_, node])
    node.ir_type == "ConditionalStatement"
    node.is_top == true
    node.type == 2
    not has_default_case(node)
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": get_path(node),
        "description": "Missing default case in switch expression - Logic may fail on unexpected values (CWE-478)"
    }
}

has_default_case(node) {
    node.is_default == true
}

has_default_case(node) {
    node.else_statement != null
    node.else_statement.is_default == true
}

Glitch_Analysis[result] {
    walk(input, [_, node])
    node.ir_type == "FunctionCall"
    node.name == "lookup"
    count(node.args) == 2
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": get_path(node),
        "description": "Lookup function missing default argument - May fail on missing keys (CWE-478)"
    }
}

get_path(node) = path {
    walk(input, [p, n])
    n == node
    count(p) > 0
    parent := p[count(p) - 1]
    parent.ir_type == "UnitBlock"
    path := parent.path
} else {
    ""
}