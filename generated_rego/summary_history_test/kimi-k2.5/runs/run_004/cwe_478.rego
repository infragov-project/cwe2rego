package glitch

import data.glitch_lib
import future.keywords.if
import future.keywords.in

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "ConditionalStatement"
    node.is_top == true
    is_switch_type(node)
    
    count_switch_branches(node) >= 2
    not switch_has_terminal_default(node)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in multi-condition expression - Switch or case statements should have a default case to handle unanticipated inputs. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "ConditionalStatement"
    node.is_top == true
    is_if_type(node)
    
    count_if_branches(node) >= 2
    not if_has_terminal_else(node)
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in multi-condition expression - If statements with multiple branches should have a final else clause to handle unanticipated inputs. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    node.ir_type == "Hash"
    is_conditional_hash(node)
    not hash_has_default_key(node)
    
    hash_count_keys(node) > 1
    
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in multi-condition expression - Configuration mapping should include a default or fallback case for unhandled keys. (CWE-478)"
    }
}

is_switch_type(cond) {
    cond.type == "SWITCH"
}

is_switch_type(cond) if {
    cond.type == 2
}

is_if_type(cond) {
    cond.type == "IF"
}

is_if_type(cond) if {
    cond.type == 1
}

count_switch_branches(start) = n if {
    n := count([x | walk(start, [_, x]); x.ir_type == "ConditionalStatement"; is_switch_type(x)])
}

count_if_branches(start) = n if {
    n := count([x | walk(start, [_, x]); x.ir_type == "ConditionalStatement"; is_if_type(x)])
}

switch_has_terminal_default(start) {
    walk(start, [_, x])
    x.ir_type == "ConditionalStatement"
    x.else_statement == null
    x.is_default == true
}

if_has_terminal_else(start) {
    walk(start, [_, x])
    x.ir_type == "ConditionalStatement"
    is_if_type(x)
    x.else_statement == null
}

hash_count_keys(hash) = n if {
    n := count([k | hash.value[k]])
}

is_conditional_hash(hash) {
    some k
    hash.value[k]
    k.ir_type == "String"
    sk := lower(k.value)
    startswith(sk, conditional_pattern(sk))
}

conditional_pattern(val) = result if {
    patterns := [
        "dev", "prod", "staging", "test", "development", "production",
        "east", "west", "north", "south", "central",
        "small", "medium", "large", "xl", "xlarge",
        "enabled", "disabled", "true", "false",
        "redhat", "debian", "ubuntu", "centos", "rhel", "amazon", "windows",
        "upstart", "systemd", "init",
        "env", "environment", "region", "zone", "tier", "size", "type", "mode",
        "version", "platform", "family", "init_type", "distro", "provider",
        "postgresql", "mysql"
    ]
    some p in patterns
    startswith(val, p)
    result := p
}

hash_has_default_key(hash) {
    some k
    hash.value[k]
    k.ir_type == "String"
    dk := lower(k.value)
    is_default_value(dk)
}

is_default_value(val) {
    val == "default"
} else {
    val == "else"
} else {
    val == "other"
} else {
    val == "catchall"
} else {
    val == "fallback"
} else {
    val == "undef"
} else {
    val == "*"
} else {
    val == "_"
} else {
    val == "true"
} else {
    val == "false"
}