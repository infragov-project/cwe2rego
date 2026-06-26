package glitch

import data.glitch_lib

has_default_in_chain(node) {
    node.is_default == true
}

has_default_in_chain(node) {
    node.else_statement.is_default == true
}

has_default_in_chain(node) {
    node.else_statement.else_statement.is_default == true
}

has_default_in_chain(node) {
    node.else_statement.else_statement.else_statement.is_default == true
}

has_default_in_chain(node) {
    node.else_statement.else_statement.else_statement.else_statement.is_default == true
}

has_default_in_chain(node) {
    node.else_statement.else_statement.else_statement.else_statement.else_statement.is_default == true
}

condition_has_boolean(cond) {
    cond.right.ir_type == "Boolean"
}

condition_has_boolean(cond) {
    cond.left.ir_type == "Boolean"
}

boolean_exhaustive_switch(sw) {
    condition_has_boolean(sw.condition)
    sw.else_statement != null
    condition_has_boolean(sw.else_statement.condition)
    sw.else_statement.else_statement == null
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, container])
    container.ir_type == "Variable"
    container.line > 0

    sw := container.value
    sw.ir_type == "ConditionalStatement"
    sw.type == "SWITCH"
    sw.is_top == true

    not has_default_in_chain(sw)
    not boolean_exhaustive_switch(sw)

    result := {
        "type": "sec_no_default_switch",
        "element": container,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - All switch/case constructs should include a default branch to handle unexpected values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, container])
    container.ir_type == "Attribute"
    container.line > 0

    sw := container.value
    sw.ir_type == "ConditionalStatement"
    sw.type == "SWITCH"
    sw.is_top == true

    not has_default_in_chain(sw)
    not boolean_exhaustive_switch(sw)

    result := {
        "type": "sec_no_default_switch",
        "element": container,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - All switch/case constructs should include a default branch to handle unexpected values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [path, sw])
    sw.ir_type == "ConditionalStatement"
    sw.type == "SWITCH"
    sw.is_top == true
    sw.line > 0

    last_key := path[count(path) - 1]
    last_key != "value"

    not has_default_in_chain(sw)
    not boolean_exhaustive_switch(sw)

    result := {
        "type": "sec_no_default_switch",
        "element": sw,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - All switch/case constructs should include a default branch to handle unexpected values. (CWE-478)"
    }
}