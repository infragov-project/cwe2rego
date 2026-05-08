package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    switch_conditionals := {c | c := conditionals[_]; c.type == "SWITCH"; c.is_top == true}
    
    switch_cond := switch_conditionals[_]
    
    # Collect all conditionals in the chain using a helper rule
    all_in_chain := collect_conditionals_in_chain(switch_cond)
    
    # Check if there's no default case in the entire chain
    not has_default_case(all_in_chain)
    
    # Check if it's not a boolean switch (which is acceptable)
    not is_boolean_switch(switch_cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": switch_cond,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - No default handling for unlisted values. (CWE-478)"
    }
}

# Helper rule to collect all conditionals in the chain without recursion
collect_conditionals_in_chain(cond) = all_cond {
    all_cond := {c | 
        c := cond
        c != null
        c := c.else_statement
    }
    all_cond := all_cond | {cond}
}

has_default_case(conditions) {
    c := conditions[_]
    c.is_default == true
}

is_boolean_switch(switch_cond) {
    switch_cond.condition.ir_type == "Equal"
    switch_cond.condition.left.ir_type == "VariableReference"
    switch_cond.condition.right.ir_type == "Boolean"
    switch_cond.else_statement != null
    switch_cond.else_statement.condition.ir_type == "Equal"
    switch_cond.else_statement.condition.left.ir_type == "VariableReference"
    switch_cond.else_statement.condition.right.ir_type == "Boolean"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, n])
    n.ir_type == "Access"
    n.left.ir_type == "Hash"
    n.right.ir_type == "VariableReference"
    
    result := {
        "type": "sec_no_default_switch",
        "element": n,
        "path": parent.path,
        "description": "Direct key access in lookup table without fallback - May lead to unhandled conditions. (CWE-478)"
    }
}