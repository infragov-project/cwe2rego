package glitch

import data.glitch_lib

# Helper to check if a condition chain has a default case
has_default_in_chain(condition) {
    condition.is_default
} else {
    condition.else_statement != null
    condition.else_statement.is_default
} else {
    condition.else_statement != null
    condition.else_statement.else_statement != null
    condition.else_statement.else_statement.is_default
} else {
    condition.else_statement != null
    condition.else_statement.else_statement != null
    condition.else_statement.else_statement.else_statement != null
    condition.else_statement.else_statement.else_statement.is_default
}

# Helper to check if a variable value is considered validated (has a concrete default)
is_validated_variable(value) {
    value.ir_type == "String"
} else {
    value.ir_type == "Integer"
} else {
    value.ir_type == "Boolean"
} else {
    value.ir_type == "Hash"
} else {
    value.ir_type == "Array"
} else {
    # Check for hiera function calls (any default value, including undef)
    value.ir_type == "FunctionCall"
    value.name == "hiera"
} else {
    # Variable references are considered validated in Puppet context
    value.ir_type == "VariableReference"
}

# Rule 1: IF conditionals without else branch
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    condition := conditions[_]
    condition.type == "IF"
    condition.is_top
    not condition.else_statement

    result := {
        "type": "sec_no_default_switch",
        "element": condition,
        "path": parent.path,
        "description": "Missing default case in conditional expression - This may lead to unhandled inputs or states. (CWE-478)"
    }
}

# Rule 2: SWITCH conditionals without default case (excluding boolean switches)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    condition := conditions[_]
    condition.type == "SWITCH"
    condition.is_top
    
    # Check if the switch condition is not a boolean check (to avoid false positives on exhaustive boolean switches)
    not is_boolean_switch(condition)
    
    # Check if there's no default case in the switch chain
    not has_default_in_chain(condition)

    result := {
        "type": "sec_no_default_switch",
        "element": condition,
        "path": parent.path,
        "description": "Missing default case in switch expression - This may lead to unhandled inputs or states. (CWE-478)"
    }
}

# Rule 3: Unvalidated input in conditionals (variables without concrete defaults)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    
    # Check if variable is used in conditionals
    conditionals := glitch_lib.all_conditional_statements(parent)
    conditional := conditionals[_]
    glitch_lib.traverse(conditional.condition, variable.name)
    
    # Check if variable has no validated default value
    not is_validated_variable(variable.value)

    result := {
        "type": "sec_no_default_switch",
        "element": variable,
        "path": parent.path,
        "description": "Unvalidated input in conditional expression - Variables without defaults or validation may lead to unhandled cases. (CWE-478)"
    }
}

# Helper to detect boolean switches (which are exhaustive by definition)
is_boolean_switch(condition) {
    condition.ir_type == "ConditionalStatement"
    condition.condition.ir_type == "Equal"
    condition.condition.right.ir_type == "Boolean"
} else {
    condition.ir_type == "ConditionalStatement"
    condition.condition.ir_type == "Equal"
    condition.condition.left.ir_type == "VariableReference"
    condition.condition.right.ir_type == "Boolean"
} else {
    # Also handle cases where the boolean is on the left side
    condition.ir_type == "ConditionalStatement"
    condition.condition.ir_type == "Equal"
    condition.condition.left.ir_type == "Boolean"
    condition.condition.right.ir_type == "VariableReference"
}