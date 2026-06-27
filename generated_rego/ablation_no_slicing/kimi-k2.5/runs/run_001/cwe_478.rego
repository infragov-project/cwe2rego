package glitch

import data.glitch_lib

security_critical_fields := {"auth", "authentication", "encrypt", "encryption", "cipher", "tls", "ssl", "password", "secret", "key", "private_key", "certificate", "acl", "firewall", "security_group", "ingress", "egress", "allow", "deny", "permit", "privilege", "sudo", "root", "admin", "role", "permission", "access"}

is_security_critical(name) {
    lower_name := lower(name)
    contains(lower_name, security_critical_fields[_])
}

has_variable_reference(node) {
    walk(node, [_, n])
    n.ir_type == "VariableReference"
}

is_switch_type(stmt) {
    stmt.type == "SWITCH"
}

# Check if condition is a simple boolean comparison with true/false only
is_boolean_condition(cond) {
    cond.ir_type == "Boolean"
}

is_boolean_condition(cond) {
    cond.ir_type == "Equal"
    cond.right.ir_type == "Boolean"
}

is_boolean_condition(cond) {
    cond.ir_type == "Equal"
    cond.left.ir_type == "Boolean"
}

# Collect all case branches in the direct else_statement chain (switches only)
collect_switch_chain(stmt) = chain {
    chain := [node |
        walk(stmt, [path, node])
        node.ir_type == "ConditionalStatement"
        node.type == "SWITCH"
        count(path) > 0
        path[count(path) - 1] == "else_statement"
    ]
}

# Count branches including the root switch
count_all_branches(stmt) = n {
    chain := collect_switch_chain(stmt)
    n := count(chain) + 1
}

# Check if any branch in the direct switch chain has is_default flag
# This only checks SWITCH statements in the direct else_statement chain,
# not nested IF statements or switches inside case bodies
has_default_in_chain(stmt) {
    walk(stmt, [path, node])
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
    node.is_default == true
    # Must be either the root or directly in else_statement chain
    count(path) == 0
} else {
    walk(stmt, [path, node])
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
    node.is_default == true
    count(path) > 0
    path[count(path) - 1] == "else_statement"
}

# Check for boolean exhaustive coverage - only true/false cases
has_boolean_exhaustive_coverage(stmt) {
    branches := collect_switch_chain(stmt)
    
    # Get all case conditions (including root)
    all_conds := {c |
        c := stmt.condition
        is_boolean_condition(c)
    } | {node.condition |
        branches[_] = node
        is_boolean_condition(node.condition)
    }
    
    count(all_conds) == 2
    
    # Must have both true and false
    count({c | all_conds[c]; c.ir_type == "Boolean"; c.value == true}) == 1
    count({c | all_conds[c]; c.ir_type == "Boolean"; c.value == false}) == 1
}

has_boolean_exhaustive_coverage(stmt) {
    branches := collect_switch_chain(stmt)
    
    all_conds := {c |
        c := stmt.condition
        c.ir_type == "Equal"
        c.right.ir_type == "Boolean"
    } | {node.condition |
        branches[_] = node
        node.condition.ir_type == "Equal"
        node.condition.right.ir_type == "Boolean"
    }
    
    count(all_conds) == 2
    
    has_true := {c | all_conds[c]; c.right.value == true}
    has_false := {c | all_conds[c]; c.right.value == false}
    
    count(has_true) == 1
    count(has_false) == 1
}

has_variable_selector(stmt) {
    has_variable_reference(stmt.condition)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, stmt])
    stmt.ir_type == "ConditionalStatement"
    is_switch_type(stmt)
    stmt.is_top == true
    
    not has_boolean_exhaustive_coverage(stmt)
    not has_default_in_chain(stmt)
    
    branches := collect_switch_chain(stmt)
    count(branches) >= 1
    
    result := {
        "type": "sec_no_default_switch",
        "element": stmt,
        "path": parent.path,
        "description": "Missing default case in conditional - Switch statement without default/fallback branch may lead to undefined behavior. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, stmt])
    stmt.ir_type == "ConditionalStatement"
    is_switch_type(stmt)
    stmt.is_top == true
    
    not has_boolean_exhaustive_coverage(stmt)
    not has_default_in_chain(stmt)
    has_variable_selector(stmt)
    
    result := {
        "type": "sec_no_default_switch",
        "element": stmt,
        "path": parent.path,
        "description": "Missing default case in variable-driven conditional - Variable-driven switch without default/fallback branch may lead to undefined behavior. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, stmt])
    stmt.ir_type == "ConditionalStatement"
    is_switch_type(stmt)
    stmt.is_top == true
    
    not has_boolean_exhaustive_coverage(stmt)
    not has_default_in_chain(stmt)
    
    # Check for security-critical attributes in case bodies
    walk(stmt, [_, inner])
    inner.ir_type == "Attribute"
    is_security_critical(inner.name)
    
    result := {
        "type": "sec_no_default_switch",
        "element": stmt,
        "path": parent.path,
        "description": "Missing default case in security-critical conditional - Incomplete conditional affecting security configuration without fallback. (CWE-478)"
    }
}