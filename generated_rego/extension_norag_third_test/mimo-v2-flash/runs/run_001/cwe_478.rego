package glitch

import data.glitch_lib

# Helper rule to check if a condition has a default branch in its chain
has_default(cond) = result {
    # Base case: current condition is default
    result := true
    cond.is_default == true
} else {
    # Recursive case: check else_statement if it exists
    cond.else_statement != null
    result := has_default(cond.else_statement)
} else {
    # No default found in chain
    result := false
}

# Rule 1: Detect missing default branch in top-level conditional statements
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all top-level conditional statements
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    
    # Focus on top-level conditions only
    cond.is_top == true
    
    # Check if there's no default in the entire chain
    not has_default(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Conditional logic without default fallback - Missing default case in multi-branch logic may lead to unpredictable behavior or security risks. (CWE-478)"
    }
}

# Rule 2: Detect lookup operations without explicit fallback (missing default argument)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Find all function calls
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for lookup-like functions common in IaC
    node.ir_type == "FunctionCall"
    regex.match("(?i)lookup|dig|fetch|find_in_map|try", node.name)
    
    # Check argument count: typically lookup(map, key) requires 2 args, 
    # but a safe default is needed (3rd arg). 
    # If args < 3, it's likely missing a default.
    count(node.args) < 3
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Lookup operation without explicit fallback - Missing default value may cause errors or unexpected behavior. (CWE-478)"
    }
}

# Rule 3: Detect variables assigned from conditional logic without a default branch
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all variables
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Check if the variable's value is a conditional statement
    var.value.ir_type == "ConditionalStatement"
    
    # Check if there's no default in the entire chain
    not has_default(var.value)
    
    result := {
        "type": "sec_no_default_switch",
        "element": var,
        "path": parent.path,
        "description": "Variable assigned from conditional logic without a default fallback - May lead to security risks if unexpected inputs bypass controls. (CWE-478)"
    }
}