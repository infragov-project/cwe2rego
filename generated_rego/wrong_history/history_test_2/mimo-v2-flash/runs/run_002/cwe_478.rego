package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]
    
    # Check for conditional statements without an else branch
    conditional.is_top == true
    not conditional.else_statement
    
    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Conditional statement missing default/else branch (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Look for map/lookup operations without default values
    all_access_ops := {n |
        walk(parent, [path, n])
        n.ir_type == "Access"
    }
    
    access := all_access_ops[_]
    
    # Check if left side is a Hash or VariableReference (map/dictionary)
    allowed_types := {"Hash", "VariableReference"}
    access_left_type := access.left.ir_type
    access_left_type in allowed_types
    
    # Check if this access is used in an assignment or function call without default
    # We look for patterns where a variable is assigned from map access
    assignment := {a |
        walk(parent, [path, a])
        a.ir_type == "Assign"
        a.left.ir_type == "VariableReference"
        a.right == access
    }
    
    count(assignment) > 0
    
    result := {
        "type": "sec_no_default_switch",
        "element": access,
        "path": parent.path,
        "description": "Map/dictionary access without default value (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]
    
    # Check for switch statements without default case
    conditional.type == 2  # SWITCH type
    conditional.is_top == true
    
    # Check if there are any child conditionals that are marked as default
    has_default := false
    walk(conditional, [path, child])
    child.ir_type == "ConditionalStatement"
    child.is_default == true
    has_default = true
    
    not has_default
    
    result := {
        "type": "sec_no_default_switch",
        "element": conditional,
        "path": parent.path,
        "description": "Switch statement missing default case (CWE-478)"
    }
}