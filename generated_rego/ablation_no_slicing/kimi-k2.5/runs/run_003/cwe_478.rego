package glitch

import data.glitch_lib

# Security-sensitive attribute names
is_security_sensitive_attr(name) {
    lower_name := lower(name)
    matches := ["mode", "owner", "group", "user", "ensure", "action", "password", "secret", "key", "token"]
    lower_name == matches[_]
} else {
    regex.match("(?i)(permission|access|auth|encrypt|ssl|tls|credential|cert)", name)
}

# Check if node contains external input (VariableReference, FunctionCall, MethodCall, Access)
has_external_input(node) {
    walk(node, [_, n])
    n.ir_type == "VariableReference"
} else {
    walk(node, [_, n])
    n.ir_type == "FunctionCall"
} else {
    walk(node, [_, n])
    n.ir_type == "MethodCall"
} else {
    walk(node, [_, n])
    n.ir_type == "Access"
}

# Count branches in a switch by following else_statement chain
count_switch_branches(cond) = num {
    branches := collect_switch_branches(cond)
    num := count(branches)
}

# Collect all branches in a switch chain (including nested switches)
collect_switch_branches(cond) = branches {
    cond.ir_type == "ConditionalStatement"
    cond.type == "SWITCH"
    
    # Get this switch and any nested ones in else_statement
    branches := {cond} | collect_nested_branches(cond.else_statement)
}

collect_nested_branches(else_stmt) = nested {
    else_stmt == null
    nested := set()
} else = nested {
    else_stmt.ir_type == "ConditionalStatement"
    else_stmt.type == "SWITCH"
    nested := {else_stmt} | collect_nested_branches(else_stmt.else_statement)
} else = nested {
    else_stmt.ir_type == "ConditionalStatement"
    else_stmt.type != "SWITCH"
    nested := collect_nested_branches(else_stmt.else_statement)
} else = nested {
    nested := set()
}

# Check if any branch in the chain is a default (catches missing default)
has_explicit_default(cond) {
    # Direct default branch
    cond.is_default == true
} else {
    # Check if else_statement ends with a default somewhere
    has_default_in_chain(cond.else_statement)
}

has_default_in_chain(null) = false

has_default_in_chain(else_stmt) = true {
    else_stmt.ir_type == "ConditionalStatement"
    else_stmt.is_default == true
}

has_default_in_chain(else_stmt) = result {
    else_stmt.ir_type == "ConditionalStatement"
    else_stmt.is_default == false
    result := has_default_in_chain(else_stmt.else_statement)
}

has_default_in_chain(else_stmt) = false {
    else_stmt.ir_type != "ConditionalStatement"
}

# Find all variables assigned in a conditional's statements
find_assigned_variables(cond) = vars {
    vars := {n.name |
        walk(cond, [_, n])
        n.ir_type == "Variable"
        n.name
    }
}

# Check if a variable is used in security-sensitive context anywhere in the scope
variable_used_in_security_context(varname, scope) {
    # Variable used in AtomicUnit attribute with security-sensitive name
    walk(scope, [_, au])
    au.ir_type == "AtomicUnit"
    
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    is_security_sensitive_attr(attr.name)
    
    # Check if attribute value contains reference to our variable
    contains_var_reference(attr.value, varname)
}

variable_used_in_security_context(varname, scope) {
    # Variable used as AtomicUnit name (resource name)
    walk(scope, [_, au])
    au.ir_type == "AtomicUnit"
    au.name.ir_type == "VariableReference"
    au.name.value == varname
    
    # Check if this atomic unit type is security-sensitive
    regex.match("(?i)(package|service|file|user|group|firewall|policy|role|vault|secret)", au.type)
}

variable_used_in_security_context(varname, scope) {
    # Variable used in important conditional checks
    walk(scope, [_, cond])
    cond.ir_type == "ConditionalStatement"
    
    walk(cond.condition, [_, ref])
    ref.ir_type == "VariableReference"
    ref.value == varname
}

# Check if expression contains a variable reference
contains_var_reference(expr, varname) {
    expr.ir_type == "VariableReference"
    expr.value == varname
} else {
    walk(expr, [_, n])
    n.ir_type == "VariableReference"
    n.value == varname
}

# Main analysis rule
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Find top-level switch statements with external input
    walk(parent, [_, cond])
    cond.ir_type == "ConditionalStatement"
    cond.type == "SWITCH"
    cond.is_top == true
    
    # Must have external input driving the condition
    has_external_input(cond.condition)
    
    # Must have multiple branches (2+) without explicit default
    branch_count := count_switch_branches(cond)
    branch_count >= 2
    not has_explicit_default(cond)
    
    # Collect all variables assigned in any branch
    assigned_vars := find_assigned_variables(cond)
    
    # At least one variable must be used in security-sensitive context
    some_varname := assigned_vars[_]
    variable_used_in_security_context(some_varname, parent)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": parent.path,
        "description": "Missing default case in multi-branch switch statement - Conditional statements without a fallback/default branch may allow unexpected values to propagate to security-sensitive configurations. (CWE-478)"
    }
}