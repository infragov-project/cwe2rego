package glitch

import data.glitch_lib

# Helper rule to check if a conditional chain has a default case without recursion
has_default_case_non_recursive(cond) {
    # Collect all conditionals in the chain by following else_statement until null
    chain := collect_conditionals(cond, [])
    # Check if any conditional in the chain is a default case
    some c in chain
    c.is_default == true
}

# Helper rule to collect conditionals in a chain without recursion
# Uses a fixed-point approach with a set to avoid infinite loops
collect_conditionals(cond, acc) = chain {
    # If we've seen this conditional before, stop (avoid cycles)
    cond in acc
    chain := acc
} else {
    # Add current conditional to accumulator
    new_acc := array.concat(acc, [cond])
    # If there's an else_statement, continue collecting
    cond.else_statement != null
    chain := collect_conditionals(cond.else_statement, new_acc)
} else {
    # Base case: no else_statement, return accumulator with current conditional
    chain := array.concat(acc, [cond])
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    cond := conditionals[_]
    cond.ir_type == "ConditionalStatement"
    cond.condition != null
    cond.type == 1
    cond.is_top == true
    
    not has_default_case_non_recursive(cond)

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in if condition chain (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    cond := conditionals[_]
    cond.ir_type == "ConditionalStatement"
    cond.condition != null
    cond.type == 2
    cond.is_top == true
    
    not has_default_case_non_recursive(cond)

    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in switch statement (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, n])
    n.ir_type == "FunctionCall"
    regex.match("(?i).*(lookup|find_in_map).*", n.name)
    count(n.args) < 3

    result := {
        "type": "sec_no_default_switch",
        "element": n,
        "path": parent.path,
        "description": "Missing default in function call that requires a default (CWE-478)"
    }
}