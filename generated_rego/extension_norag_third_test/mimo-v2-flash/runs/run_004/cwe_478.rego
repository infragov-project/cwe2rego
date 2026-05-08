package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, stmt])
    stmt.ir_type == "ConditionalStatement"
    stmt.is_top == true
    stmt.type == 1  # IF type
    
    # Check if there's an else_statement chain without default
    current := stmt
    has_default := false
    while current.else_statement != null {
        current := current.else_statement
        if current.is_default {
            has_default := true
        }
    }
    
    not has_default
    
    result := {
        "type": "sec_no_default_switch",
        "element": stmt,
        "path": parent.path,
        "description": "Missing default case in conditional expression - All conditional branches should have a default case to handle unexpected values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    regex.match("(?i).*lookup.*|.*get.*|.*fetch.*", node.name)
    count(node.args) < 2
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Lookup operation without default fallback - Map lookups should include a default value for missing keys. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "ConditionalStatement"
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Variable assignment with conditional expression without validation - Variables used in conditions should have proper validation. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    
    # Check each argument for conditional statements
    some arg in node.args
    walk(arg, [_, subnode])
    subnode.ir_type == "ConditionalStatement"
    subnode.is_top == true
    subnode.type == 1  # IF type
    
    # Check if the conditional in the argument has no default
    current := subnode
    has_default := false
    while current.else_statement != null {
        current := current.else_statement
        if current.is_default {
            has_default := true
        }
    }
    
    not has_default
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Function call with incomplete conditional logic - Function arguments should handle all possible cases. (CWE-478)"
    }
}