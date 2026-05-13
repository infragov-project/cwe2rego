package glitch

import data.glitch_lib

# Set of function names that typically require a default argument in lookups
lookup_functions := {"lookup", "index"}

# Check if a conditional statement has a default case in its chain
has_default_case(cond) := result {
    # Start by checking if the current condition is a default
    cond.is_default == true
    result := true
}

has_default_case(cond) := result {
    # If not default, check the else_statement chain
    cond.else_statement != null
    result := has_default_case(cond.else_statement)
}

has_default_case(cond) := false {
    # Base case: no default found in the chain
    true
}

# Rule 1: Detect incomplete conditional chains (missing else or default)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    cond.is_default == false
    not has_default_case(cond)

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default handler in conditional expression - Incomplete if/else or switch case without default. (CWE-478)"
    }
}

# Rule 2: Detect unhandled map lookups without fallback
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    node.name in lookup_functions
    count(node.args) < 3

    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default handler in map lookup - Lookup function without fallback value. (CWE-478)"
    }
}

# Rule 3: Detect variables without default values
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    var.value.ir_type == "Null" or var.value.ir_type == "Undef"

    result := {
        "type": "sec_no_default_switch",
        "element": var,
        "path": parent.path,
        "description": "Missing default value for variable - Variable without default value. (CWE-478)"
    }
}