package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    condition := conditions[_]
    condition.type == "SWITCH"
    condition.is_default == false
    condition.is_top == true
    
    # Check if there's no default case in the switch chain
    not has_default_in_chain(condition)
    
    result := {
        "type": "sec_no_default_switch",
        "element": condition,
        "path": parent.path,
        "description": "Missing default case in switch expression - No default case provided in the switch chain. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    condition := conditions[_]
    condition.type == "IF"
    condition.is_default == false
    condition.is_top == true
    condition.else_statement == null
    
    result := {
        "type": "sec_no_default_switch",
        "element": condition,
        "path": parent.path,
        "description": "Missing default case in conditional expression - IF statement without else branch. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "FunctionCall"
    regex.match("(?i)lookup|findinmap", node.name)
    count(node.args) < 3
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default value in lookup function - Lookup function without fallback value. (CWE-478)"
    }
}

# Helper rule to check if a condition chain has a default case
has_default_in_chain(condition) {
    condition.is_default == true
}

has_default_in_chain(condition) {
    condition.else_statement != null
    has_default_in_chain(condition.else_statement)
}