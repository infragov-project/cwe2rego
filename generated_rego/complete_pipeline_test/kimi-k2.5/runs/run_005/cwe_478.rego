package glitch

import data.glitch_lib
import future.keywords.in

is_switch_type(cond) {
    cond.type == "SWITCH"
}

is_if_type(cond) {
    cond.type == "IF"
}

has_default_or_else(cond) {
    cond.is_default == true
}

has_default_or_else(cond) {
    some item in walk(cond)
    item[1].is_default == true
}

external_sources := {"VariableReference", "FunctionCall", "MethodCall", "Access"}

has_external_source(node) {
    node.ir_type == external_sources[_]
}

has_external_source(node) {
    some item in walk(node)
    item[1].ir_type == external_sources[_]
}

collect_switch_chain(start) = result {
    result := chain_reachable(start, [start])
}

chain_reachable(node, acc) = result {
    node.else_statement == null
    result := acc
} else = result {
    node.else_statement.ir_type == "ConditionalStatement"
    is_switch_type(node.else_statement)
    new_acc := array.concat(acc, [node.else_statement])
    result := chain_reachable(node.else_statement, new_acc)
} else = result {
    result := acc
}

count_branches_in_chain(start) = n {
    chain := collect_switch_chain(start)
    unique := {node | some node in chain}
    n := count(unique)
}

chain_has_default(start) {
    some node in collect_switch_chain(start)
    node.is_default == true
}

has_complex_condition(cond) {
    cond.ir_type == "Equal"
    has_external_source(cond.left)
}

default_terminator(key) {
    lower(key) == "default"
} else {
    lower(key) == "else"
} else {
    lower(key) == "*"
} else {
    lower(key) == "_"
}

hash_has_default(hash_node) {
    some key in object.keys(hash_node.value)
    key.ir_type == "String"
    default_terminator(key.value)
}

selection_context_names := {"type", "mode", "family", "platform", "system", "provider", "backend", "driver", "engine", "strategy", "format", "protocol", "method", "init_type", "osfamily", "plan", "tier", "sku", "size", "family"}

is_selection_context(node) {
    some parent in [item[1] | some item in walk(input); item[1].value == node]
    parent.ir_type == "KeyValue"
    name_lower := lower(parent.name)
    name_lower == selection_context_names[_]
} else {
    some parent in [item[1] | some item in walk(input); item[1].value == node]
    parent.ir_type == "Attribute"
    name_lower := lower(parent.name)
    name_lower == selection_context_names[_]
} else {
    some parent in [item[1] | some item in walk(input); item[1].value == node]
    parent.ir_type == "Variable"
    name_lower := lower(parent.name)
    name_lower == selection_context_names[_]
} else {
    some item in walk(input)
    item[1].ir_type == "Assign"
    some inner in walk(item[1])
    inner[1] == node
}

pattern_methods := {"select", "match", "when", "case", "find", "detect", "lookup", "fetch", "lookupvar"}

is_pattern_method(method_name) {
    lowered := lower(method_name)
    lowered == pattern_methods[_]
}

method_has_default_arg(args) {
    some arg in args
    arg.ir_type == "String"
    default_terminator(arg.value)
}

method_has_default_arg(args) {
    some arg in args
    some item in walk(arg)
    item[1].ir_type == "String"
    default_terminator(item[1].value)
}

collect_if_chain(start) = result {
    result := if_chain_reachable(start, [start])
}

if_chain_reachable(node, acc) = result {
    node.else_statement == null
    result := acc
} else = result {
    node.else_statement.ir_type == "ConditionalStatement"
    is_if_type(node.else_statement)
    new_acc := array.concat(acc, [node.else_statement])
    result := if_chain_reachable(node.else_statement, new_acc)
} else = result {
    result := acc
}

count_if_branches(start) = n {
    chain := collect_if_chain(start)
    unique := {node | some node in chain}
    n := count(unique)
}

if_chain_has_final_else(start) {
    chain_collected := collect_if_chain(start)
    some last_node in chain_collected
    last_node.else_statement == null
    count([true | some node in chain_collected; node.else_statement != null]) >= 1
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some item in walk(parent)
    item[1].ir_type == "ConditionalStatement"
    is_switch_type(item[1])
    
    count_branches_in_chain(item[1]) >= 2
    not chain_has_default(item[1])
    
    cond := item[1].condition
    has_external_source(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": item[1],
        "path": parent.path,
        "description": "Missing Default Case in Switch Statement - Multi-branch conditional lacks comprehensive fallback mechanism for unhandled values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some item in walk(parent)
    item[1].ir_type == "ConditionalStatement"
    is_switch_type(item[1])
    
    count_branches_in_chain(item[1]) >= 2
    not chain_has_default(item[1])
    
    cond := item[1].condition
    has_complex_condition(cond)
    
    result := {
        "type": "sec_no_default_switch",
        "element": item[1],
        "path": parent.path,
        "description": "Missing Default Case in Switch Statement - Multi-branch conditional lacks comprehensive fallback mechanism for unhandled values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some item in walk(parent)
    item[1].ir_type == "ConditionalStatement"
    is_switch_type(item[1])
    item[1].is_top == true
    
    count_branches_in_chain(item[1]) >= 2
    not chain_has_default(item[1])
    
    some inner in walk(item[1].condition)
    has_external_source(inner[1])
    
    result := {
        "type": "sec_no_default_switch",
        "element": item[1],
        "path": parent.path,
        "description": "Missing Default Case in Switch Statement - Multi-branch conditional lacks comprehensive fallback mechanism for unhandled values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some item in walk(parent)
    item[1].ir_type == "Hash"
    keys := object.keys(item[1].value)
    count(keys) > 1
    not hash_has_default(item[1])
    is_selection_context(item[1])
    
    result := {
        "type": "sec_no_default_switch",
        "element": item[1],
        "path": parent.path,
        "description": "Missing Default Case in Switch Statement - Lookup table lacks comprehensive fallback for unhandled keys. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some item in walk(parent)
    item[1].ir_type == "MethodCall"
    
    is_pattern_method(item[1].method)
    count(item[1].args) >= 1
    not method_has_default_arg(item[1].args)
    
    result := {
        "type": "sec_no_default_switch",
        "element": item[1],
        "path": parent.path,
        "description": "Missing Default Case in Switch Statement - Pattern matching method lacks comprehensive fallback handler. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some item in walk(parent)
    item[1].ir_type == "ConditionalStatement"
    is_if_type(item[1])
    
    count_if_branches(item[1]) >= 2
    not if_chain_has_final_else(item[1])
    
    has_external_source(item[1].condition)
    
    result := {
        "type": "sec_no_default_switch",
        "element": item[1],
        "path": parent.path,
        "description": "Missing Default Case in Switch Statement - If-else chain lacks comprehensive fallback (final else clause). (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some item in walk(parent)
    item[1].ir_type == "ConditionalStatement"
    is_if_type(item[1])
    item[1].is_top == true
    
    count_if_branches(item[1]) >= 2
    not if_chain_has_final_else(item[1])
    
    cond := item[1].condition
    cond.ir_type == "Equal"
    has_external_source(cond.left)
    
    result := {
        "type": "sec_no_default_switch",
        "element": item[1],
        "path": parent.path,
        "description": "Missing Default Case in Switch Statement - If-else chain lacks comprehensive fallback (final else clause). (CWE-478)"
    }
}