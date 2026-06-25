package glitch

import data.glitch_lib
import future.keywords

contextual_fields := {
    "environment", "env", "stage", "deployment_stage", "workspace",
    "region", "availability_zone", "location", "datacenter",
    "instance_type", "machine_type", "size", "tier", "sku",
    "compliance_regime", "security_level", "classification", "sensitivity",
    "vpc_tier", "subnet_type", "network_zone", "isolation_level",
    "feature_flag", "toggle", "variant", "mode",
    "provider", "cloud", "platform", "platform_family", "vendor",
    "osfamily", "operatingsystem", "lsbdistcodename", "init_type"
}

extract_all_text(node) = strs {
    strs := {lower(s) |
        walk(node, [_, n])
        n.ir_type == "String"
        s := n.value
    } | {lower(s) |
        walk(node, [_, n])
        n.ir_type == "VariableReference"
        s := n.value
    } | {lower(s) |
        walk(node, [_, n])
        n.ir_type == "MethodCall"
        s := n.method
    } | {lower(s) |
        walk(node, [_, n])
        n.ir_type == "FunctionCall"
        s := n.name
    } | {lower(s) |
        walk(node, [_, n])
        n.ir_type == "Access"
        n.right.ir_type == "String"
        s := n.right.value
    }
}

has_contextual_field_reference(node) {
    strs := extract_all_text(node)
    some str in strs
    some field in contextual_fields
    contains(str, field)
}

is_conditional_without_default(node) {
    node.ir_type == "ConditionalStatement"
    node.type == "SWITCH"
    not node.is_default
    not chain_ends_with_default(node)
}

is_conditional_without_default(node) {
    node.ir_type == "ConditionalStatement"
    node.type == "IF"
    not node.is_default
    not chain_ends_with_default(node)
}

chain_ends_with_default(node) {
    node.is_default == true
}

chain_ends_with_default(node) {
    node.condition.ir_type == "Null"
}

chain_ends_with_default(node) {
    node.else_statement != null
    chain_ends_with_default(node.else_statement)
}

count_chain_branches(node) = n {
    n := 1 + count_chain_branches(node.else_statement)
} else = 1 {
    node.else_statement == null
} else = 0 {
    true
}

is_multi_branch(node) {
    count_chain_branches(node) >= 2
}

check_conditional_in_node(node, parent) = result {
    is_conditional_without_default(node)
    is_multi_branch(node)
    has_contextual_field_reference(node.condition)
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing Default Case in Multiple Condition Expression - Conditional without default/fallback for IaC contextual values. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, node])
    result := check_conditional_in_node(node, parent)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [_, var])
    var.ir_type == "Variable"
    var.value.ir_type == "ConditionalStatement"
    
    result := check_conditional_in_node(var.value, parent)
}