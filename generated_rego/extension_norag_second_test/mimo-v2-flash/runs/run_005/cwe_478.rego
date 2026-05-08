package glitch

import data.glitch_lib

# Rule to detect missing default branch in SWITCH conditionals
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    stmt := conditionals[_]
    stmt.type == "SWITCH"
    stmt.is_top == true
    not stmt.is_default
    stmt.else_statement == null
    result := {
        "type": "sec_no_default_switch",
        "element": stmt,
        "path": parent.path,
        "description": "Missing default branch in conditional logic - Conditional statements should handle all possible cases. (CWE-478)"
    }
}

# Rule to detect missing else clause in IF conditionals
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditionals := glitch_lib.all_conditional_statements(parent)
    stmt := conditionals[_]
    stmt.type == "IF"
    stmt.is_top == true
    stmt.else_statement == null
    result := {
        "type": "sec_no_default_switch",
        "element": stmt,
        "path": parent.path,
        "description": "Missing else clause in conditional logic - IF statements should have an else branch to handle all cases. (CWE-478)"
    }
}

# Rule to detect unhandled enumeration or state selection via map lookup
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    walk(node, [path, n])
    n.ir_type == "Access"
    n.left.ir_type == "VariableReference"
    allowed_types := {"String", "VariableReference"}
    allowed_types[n.right.ir_type]
    not has_validation_for_lookup(n, parent)
    result := {
        "type": "sec_no_default_switch",
        "element": n,
        "path": parent.path,
        "description": "Unhandled map lookup - Map lookups should have validation or default values. (CWE-478)"
    }
}

# Helper rule to check if there's validation for a map lookup
has_validation_for_lookup(access_node, parent) {
    conditionals := glitch_lib.all_conditional_statements(parent)
    cond := conditionals[_]
    walk(cond, [path, n])
    n.ir_type == "Equal"
    n.left.ir_type == "VariableReference"
    n.left.value == access_node.right.value
}

# Rule to detect missing fallback in resource creation loops
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    walk(node, [path, n])
    n.ir_type == "FunctionCall"
    regex.match("(?i)for_each|for|foreach|loop", n.name)
    not has_fallback_for_loop(n, parent)
    result := {
        "type": "sec_no_default_switch",
        "element": n,
        "path": parent.path,
        "description": "Missing fallback in resource creation loops - Loops should handle all items or have explicit filtering. (CWE-478)"
    }
}

# Helper rule to check if a loop has fallback handling
has_fallback_for_loop(loop_node, parent) {
    conditionals := glitch_lib.all_conditional_statements(parent)
    cond := conditionals[_]
    walk(cond, [path, n])
    n.ir_type == "VariableReference"
    true
}