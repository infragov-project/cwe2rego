package glitch

import data.glitch_lib

conditional_has_default(node) {
    walk(node, [_, n])
    n.ir_type == "ConditionalStatement"
    n.is_default == true
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    node := conditions[_]
    node.is_top == true
    not conditional_has_default(node)

    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in conditional expression - Conditional structures should have a default/else branch to handle all possible input values. (CWE-478)"
    }
}

has_deny_effect(attrs) {
    attr := attrs[_]
    attr.name == "effect"
    attr.value.ir_type == "String"
    lower(attr.value.value) == "deny"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    allow_attr := attrs[_]
    allow_attr.name == "effect"
    allow_attr.value.ir_type == "String"
    lower(allow_attr.value.value) == "allow"
    not has_deny_effect(attrs)

    result := {
        "type": "sec_no_default_switch",
        "element": allow_attr,
        "path": parent.path,
        "description": "Policy without explicit deny - Permission policies should include a terminal deny statement to prevent unintended access. (CWE-478)"
    }
}

has_default_action(attrs) {
    attr := attrs[_]
    regex.match("(?i).*default.*(action|rule|policy).*", attr.name)
}

has_default_action(attrs) {
    attr := attrs[_]
    regex.match("(?i).*(action|rule|policy).*default.*", attr.name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    regex.match("(?i).*(rule|listener|routing|forwarding|acl|firewall|ingress|egress).*", node.type)
    attrs := glitch_lib.all_attributes(node)
    not has_default_action(attrs)

    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default action in rule set - Rule collections should define a catch-all default action for unmatched inputs or traffic. (CWE-478)"
    }
}