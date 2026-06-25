package glitch

import data.glitch_lib
import future.keywords.in

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some path, n in walk(parent)
    n.ir_type == "ConditionalStatement"
    n.type == 2
    n.is_top == true
    
    has_multiple_branches_no_default(n)
    
    result := {
        "type": "sec_no_default_switch",
        "element": n,
        "path": parent.path,
        "description": "Missing default case in multi-condition construct - Add a default/fallback branch to handle unexpected values. (CWE-478)"
    }
}

has_multiple_branches_no_default(start) {
    count_branches(start) >= 2
    not any_default_in_chain(start)
}

count_branches(start) = nbranches {
    all_nodes := collect_chain_nodes(start)
    nbranches := count(all_nodes)
}

collect_chain_nodes(start) = nodes {
    nodes := {n |
        some path, n in walk(start)
        n.ir_type == "ConditionalStatement"
        reaches_via_else(start, n)
    }
}

reaches_via_else(start, target) {
    target.line == start.line
}

reaches_via_else(start, target) {
    current := get_else_target(start)
    current != null
    current.line != start.line
    reaches_via_else(current, target)
}

get_else_target(node) = result {
    node.else_statement
    result := node.else_statement
} else = null {
    true
}

any_default_in_chain(start) {
    some path, n in walk(start)
    n.ir_type == "ConditionalStatement"
    n.is_default == true
    reaches_via_else(start, n)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some path, node in walk(parent)
    node.ir_type == "Attribute"
    node.value.ir_type == "Hash"
    
    hash_obj := node.value.value
    count([k | some k in object.keys(hash_obj)]) >= 2
    not has_default_hash_key(hash_obj)
    some_discrete_key_exists(hash_obj)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in mapping construct - Add a default/fallback entry to handle unexpected keys. (CWE-478)"
    }
}

has_default_hash_key(hash_obj) {
    some k in object.keys(hash_obj)
    is_string_key_with_default(k)
}

is_string_key_with_default(key) {
    key.ir_type == "String"
    lower(key.value) == "default"
}

is_string_key_with_default(key) {
    key.ir_type == "String"
    lower(key.value) == "fallback"
}

is_string_key_with_default(key) {
    key.ir_type == "String"
    lower(key.value) == "else"
}

is_string_key_with_default(key) {
    key.ir_type == "String"
    key.value == "*"
}

is_string_key_with_default(key) {
    key.ir_type == "String"
    lower(key.value) == "other"
}

some_discrete_key_exists(hash_obj) {
    some k in object.keys(hash_obj)
    k.ir_type == "String"
    is_discrete_value(k.value)
}

is_discrete_value(str) {
    lower(str) == "debian"
}

is_discrete_value(str) {
    lower(str) == "rhel"
}

is_discrete_value(str) {
    lower(str) == "centos"
}

is_discrete_value(str) {
    lower(str) == "ubuntu"
}

is_discrete_value(str) {
    lower(str) == "redhat"
}

is_discrete_value(str) {
    lower(str) == "upstart"
}

is_discrete_value(str) {
    lower(str) == "systemd"
}

is_discrete_value(str) {
    lower(str) == "init"
}

is_discrete_value(str) {
    lower(str) == "prod"
}

is_discrete_value(str) {
    lower(str) == "staging"
}

is_discrete_value(str) {
    lower(str) == "dev"
}