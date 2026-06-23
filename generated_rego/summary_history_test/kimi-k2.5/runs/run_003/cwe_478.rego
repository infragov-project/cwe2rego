package glitch

import data.glitch_lib
import future.keywords.if
import future.keywords.in

is_explicitly_default(cond) if cond.is_default == true

is_explicitly_default(cond) if cond.condition.ir_type == "Null"

collect_else_chain(root) = result {
    result := {node | 
        some pair in walk(root)
        some node in [pair[1]]
        node.ir_type == "ConditionalStatement"
        node != root
        is_linked_via_else(root, node)
    }
}

is_linked_via_else(root, target) if root.else_statement == target

is_linked_via_else(root, target) {
    root.else_statement != null
    is_linked_via_else(root.else_statement, target)
}

count_branches(cond) = n {
    chain := collect_else_chain(cond)
    n := count(chain) + 1
}

has_explicit_default_in_chain(root) {
    is_explicitly_default(root)
}

has_explicit_default_in_chain(root) {
    some node in collect_else_chain(root)
    is_explicitly_default(node)
}

is_variable_driven(cond) {
    some pair in walk(cond.condition)
    n := pair[1]
    n.ir_type in {"VariableReference", "Access", "MethodCall", "FunctionCall"}
}

affects_security_configuration(cond) {
    some pair in walk(cond)
    node := pair[1]
    node.ir_type == "KeyValue"
    is_security_sensitive_name(node.name)
}

is_security_sensitive_name(name) {
    lower(name) in {"user", "owner", "group", "mode", "permissions", "syslog_user", "service", "daemon_user", "ssl", "auth", "password", "token", "secret", "access", "cert", "key", "encryption"}
}

find_all_conditionals(node) = {c | 
    some pair in walk(node)
    c := pair[1]
    c.ir_type == "ConditionalStatement"
}

Glitch_Analysis[result] {
    some module in input.modules
    some block in module.blocks
    
    conds := find_all_conditionals(block)
    cond := conds[_]
    
    cond.is_top == true
    cond.type == "SWITCH"
    count_branches(cond) >= 2
    not has_explicit_default_in_chain(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": block.path,
        "description": "Missing default case in multiple condition expression - SWITCH statement with multiple branches lacks a default/catch-all case to handle unhandled values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    some module in input.modules
    some block in module.blocks
    
    conds := find_all_conditionals(block)
    cond := conds[_]
    
    cond.is_top == true
    cond.type == "IF"
    count_branches(cond) >= 3
    not has_explicit_default_in_chain(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": block.path,
        "description": "Missing default case in multiple condition expression - IF-ELSIF chain with multiple branches lacks a default/catch-all case to handle unhandled values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    some module in input.modules
    some block in module.blocks
    
    conds := find_all_conditionals(block)
    cond := conds[_]
    
    cond.is_top == true
    affects_security_configuration(cond)
    count_branches(cond) >= 2
    not has_explicit_default_in_chain(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": block.path,
        "description": "Missing default case in multiple condition expression - Conditional affecting security configuration lacks a default/catch-all case to handle unhandled values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    some module in input.modules
    some block in module.blocks
    
    conds := find_all_conditionals(block)
    cond := conds[_]
    
    cond.is_top == true
    is_variable_driven(cond)
    count_branches(cond) >= 2
    not has_explicit_default_in_chain(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": cond,
        "path": block.path,
        "description": "Missing default case in multiple condition expression - Variable-driven conditional lacks a default/catch-all case to handle unhandled input values. (CWE-478)"
    }
}