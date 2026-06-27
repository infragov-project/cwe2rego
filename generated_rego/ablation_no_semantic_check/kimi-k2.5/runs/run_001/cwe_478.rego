package glitch

import data.glitch_lib
import future.keywords.in

# Check if a conditional statement is a switch type without default
is_switch_without_default(stmt) {
    stmt.type == 2
    not stmt.is_default
    not has_else_or_default(stmt)
}

has_else_or_default(stmt) {
    stmt.else_statement != null
}

has_else_or_default(stmt) {
    stmt.is_default == true
}

# Check for multi-branch conditional without default using walk to traverse chain
check_missing_default_in_conditional(stmt) {
    stmt.type == 1
    
    chain := {s | walk(stmt, [_, s]); s.ir_type == "ConditionalStatement"}
    
    count(chain) > 2
    
    not any_is_default(chain)
}

any_is_default(chain) {
    some s in chain
    s.is_default == true
}

# Check for explicit value matching without wildcard/default in hash/map structures
check_hash_without_default(hash) {
    hash.ir_type == "Hash"
    keys := [k | k := hash.value[_]]
    count(keys) > 2
    not has_wildcard_key(keys)
}

has_wildcard_key(keys) {
    key := keys[_]
    key.ir_type == "String"
    regex.match("^\\*|default|else|_.*", key.value)
}

# Check for validation/allowed values without catch-all using case-insensitive matching
check_validation_without_catchall(attr) {
    attr.name
    regex.match("(?i).*allowed.*", attr.name)
    attr.value.ir_type == "Array"
    values := attr.value.value
    count(values) > 0
    not has_catchall_value(values)
}

check_validation_without_catchall(attr) {
    attr.name
    regex.match("(?i).*validation.*", attr.name)
    attr.value.ir_type == "Array"
    values := attr.value.value
    count(values) > 0
    not has_catchall_value(values)
}

has_catchall_value(values) {
    val := values[_]
    val.ir_type == "String"
    regex.match("\\*|any|default|unknown|other", val.value)
}

# Check for conditional output/assignment without false/else case
check_conditional_assignment_without_else(attr) {
    attr.value.ir_type == "ConditionalStatement"
    not attr.value.else_statement
}

# Main detection: Switch statements without default case
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conditions := glitch_lib.all_conditional_statements(parent)
    stmt := conditions[_]
    
    is_switch_without_default(stmt)
    
    result := {
        "type": "sec_no_default_switch",
        "element": stmt,
        "path": parent.path,
        "description": "Missing default case in switch/multiple condition expression - Unhandled cases may lead to unexpected behavior or security issues. (CWE-478)"
    }
}

# Main detection: Multi-branch if-else without final else (default)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    conditions := glitch_lib.all_conditional_statements(parent)
    stmt := conditions[_]
    
    check_missing_default_in_conditional(stmt)
    
    result := {
        "type": "sec_no_default_switch",
        "element": stmt,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Unhandled cases may lead to unexpected behavior or security issues. (CWE-478)"
    }
}

# Detection: Hash/map structures with explicit keys but no default/wildcard
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    check_hash_without_default(var.value)
    
    result := {
        "type": "sec_no_default_switch",
        "element": var,
        "path": parent.path,
        "description": "Missing default case in mapping structure - No catch-all handler for unmapped keys may lead to missing configuration. (CWE-478)"
    }
}

# Detection: Attributes with validation constraints without catch-all
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    au := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(au)
    attr := attrs[_]
    
    check_validation_without_catchall(attr)
    
    result := {
        "type": "sec_no_default_switch",
        "element": attr,
        "path": parent.path,
        "description": "Missing default/catch-all in validation constraint - Unvalidated input may pass through without proper handling. (CWE-478)"
    }
}

# Detection: Conditional assignments without false/else branch
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    check_conditional_assignment_without_else(var)
    
    result := {
        "type": "sec_no_default_switch",
        "element": var,
        "path": parent.path,
        "description": "Missing default case in conditional assignment - Ternary or conditional expression without fallback may lead to undefined values. (CWE-478)"
    }
}