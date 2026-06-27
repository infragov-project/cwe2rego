package glitch

import data.glitch_lib

is_dynamic_source(node) {
    node.ir_type == "VariableReference"
}

is_dynamic_source(node) {
    node.ir_type == "FunctionCall"
}

is_dynamic_source(node) {
    node.ir_type == "MethodCall"
}

is_dynamic_source(node) {
    node.ir_type == "Access"
}

has_dynamic_child(node) {
    walk(node, [_, child])
    child != node
    is_dynamic_source(child)
}

is_switch_type(node) {
    node.type == "SWITCH"
}

is_switch_type(node) {
    node.type == 2
}

has_default_branch(node) {
    node.ir_type == "ConditionalStatement"
    node.is_default == true
}

has_else_statement(node) {
    node.ir_type == "ConditionalStatement"
    node.else_statement != null
}

has_default_in_else(node) {
    node.ir_type == "ConditionalStatement"
    node.else_statement != null
    check_default_in_chain(node.else_statement)
}

check_default_in_chain(node) {
    has_default_branch(node)
}

check_default_in_chain(node) {
    node.ir_type == "ConditionalStatement"
    node.else_statement != null
    check_default_in_chain(node.else_statement)
}

has_true_boolean_branch(node) {
    walk(node, [_, child])
    child.ir_type == "ConditionalStatement"
    child.condition.ir_type == "Equal"
    child.condition.right.ir_type == "Boolean"
    child.condition.right.value == true
}

has_false_boolean_branch(node) {
    walk(node, [_, child])
    child.ir_type == "ConditionalStatement"
    child.condition.ir_type == "Equal"
    child.condition.right.ir_type == "Boolean"
    child.condition.right.value == false
}

is_complete_boolean_coverage(node) {
    has_true_boolean_branch(node)
    has_false_boolean_branch(node)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [path, node])
    node.ir_type == "ConditionalStatement"
    
    is_switch_type(node)
    
    node.is_top == true

    has_dynamic_child(node.condition)

    not has_default_branch(node)
    not has_default_in_else(node)

    not is_complete_boolean_coverage(node)

    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in switch statement - Switch statements should have a default case to handle unexpected values. (CWE-478)"
    }
}