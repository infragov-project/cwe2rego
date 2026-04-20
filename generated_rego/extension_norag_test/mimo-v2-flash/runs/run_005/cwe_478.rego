package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    condition := conditions[_]
    condition.ir_type == "ConditionalStatement"
    condition.type == "SWITCH"
    condition.is_top == true
    
    # Check if there are any case branches (non-default)
    case_branches := {stmt |
        walk(condition, [path, stmt])
        stmt.ir_type == "ConditionalStatement"
        stmt.type == "SWITCH"
        stmt.is_default == false
    }
    count(case_branches) > 0
    
    # Check if there's no default branch in the entire switch chain
    default_cases := {node |
        walk(condition, [path, node])
        node.ir_type == "ConditionalStatement"
        node.type == "SWITCH"
        node.is_default == true
    }
    count(default_cases) == 0
    
    result := {
        "type": "sec_no_default_switch",
        "element": condition,
        "path": parent.path,
        "description": "Missing default case in switch statement (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    condition := conditions[_]
    condition.ir_type == "ConditionalStatement"
    condition.type == "IF"
    condition.is_top == true
    
    # Check if there's no else branch in the entire if-else chain
    has_else_branch := false
    current := condition
    while {
        current.ir_type == "ConditionalStatement"
        current.type == "IF"
        current.else_statement != null
        current.else_statement.ir_type == "ConditionalStatement"
        current.else_statement.is_default == true
    } {
        has_else_branch := true
        current := current.else_statement
    }
    
    # Alternative: walk the tree to find any default branch
    default_branches := {node |
        walk(condition, [path, node])
        node.ir_type == "ConditionalStatement"
        node.type == "IF"
        node.is_default == true
    }
    
    not has_else_branch
    count(default_branches) == 0
    
    result := {
        "type": "sec_no_default_switch",
        "element": condition,
        "path": parent.path,
        "description": "Missing else branch in if-else chain (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    function_calls := {n |
        walk(parent, [path, n])
        n.ir_type == "FunctionCall"
    }
    call := function_calls[_]
    
    # Check for lookup functions without default
    lookup_functions := {"lookup", "get", "find_in_map", "select"}
    count([x | x := lookup_functions[_]; x == call.name]) > 0
    
    # Check if function has exactly 2 arguments (missing default)
    count(call.args) == 2
    
    result := {
        "type": "sec_no_default_switch",
        "element": call,
        "path": parent.path,
        "description": "Lookup function without default value (CWE-478)"
    }
}