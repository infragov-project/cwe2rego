package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_conds := glitch_lib.all_conditional_statements(parent)
    node := all_conds[_]
    node.ir_type == "ConditionalStatement"
    node.is_top
    # Check if there's a default case in the chain by walking the else_statement chain
    not has_default_in_chain(node)
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - This might lead to undefined behavior or security gaps. (CWE-478)"
    }
}

# Helper rule to check if a conditional chain has a default case
# Uses iterative approach by checking the else_statement chain
has_default_in_chain(node) {
    node.is_default
}

has_default_in_chain(node) {
    node.else_statement != null
    node.else_statement.ir_type == "ConditionalStatement"
    has_default_in_chain(node.else_statement)
}

has_default_in_chain(node) {
    node.else_statement != null
    node.else_statement.ir_type == "Block"
    # Block in else means we reached the end of the chain without finding a default
    # This should return false, but we need to explicitly handle this case
    false
}