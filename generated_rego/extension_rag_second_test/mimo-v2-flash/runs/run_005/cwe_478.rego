package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conditionals := glitch_lib.all_conditional_statements(parent)
    cs := conditionals[_]
    cs.type == "SWITCH"
    cs.is_top == true
    
    # Check if there's a default case in the chain without recursion
    not has_default_in_chain(cs)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cs,
        "path": parent.path,
        "description": "Missing default case in switch statement - Unhandled conditions may lead to security failures. (CWE-478)"
    }
}

# Helper rule to check if a switch statement has a default case in its chain
has_default_in_chain(cs) := true {
    cs.is_default == true
}

has_default_in_chain(cs) := true {
    cs.else_statement != null
    cs.else_statement.is_default == true
}

has_default_in_chain(cs) := true {
    cs.else_statement != null
    cs.else_statement.else_statement != null
    cs.else_statement.else_statement.is_default == true
}

has_default_in_chain(cs) := true {
    cs.else_statement != null
    cs.else_statement.else_statement != null
    cs.else_statement.else_statement.else_statement != null
    cs.else_statement.else_statement.else_statement.is_default == true
}

has_default_in_chain(cs) := true {
    cs.else_statement != null
    cs.else_statement.else_statement != null
    cs.else_statement.else_statement.else_statement != null
    cs.else_statement.else_statement.else_statement.else_statement != null
    cs.else_statement.else_statement.else_statement.else_statement.is_default == true
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    nodes := {n |
        walk(parent, [path, n])
        n.ir_type == "FunctionCall"
        # Check for functions that typically require defaults
        n.name in {"lookup", "find_in_map", "select"}
        count(n.args) < 3  # Typically these functions need at least 3 arguments with default
    }
    node := nodes[_]
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default value in function call - Function may fail or misbehave without fallback. (CWE-478)"
    }
}