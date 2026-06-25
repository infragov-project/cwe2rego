package glitch

import data.glitch_lib

has_default_branch(node) {
    walk(node, [_, n])
    n.ir_type == "ConditionalStatement"
    n.is_default == true
}

has_default_handling_attr(attrs) {
    attr := attrs[_]
    regex.match("(?i)(default|fallback|catch.?all|deny.?all|on.?failure|on.?error|otherwise|unmatched|drop.?all)", attr.name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conds := glitch_lib.all_conditional_statements(parent)
    node := conds[_]
    node.is_top == true
    not has_default_branch(node)
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default case in multiple condition expression - Conditional chains should always include a default or else branch to handle all possible unmatched cases. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i)^(rules?|policies|policy|actions?|effects?|conditions?|filters?)$", attr.name)
    not has_default_handling_attr(attrs)
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default action in policy or rule definition - Policy and rule definitions should include a default or fallback behavior for unmatched conditions. (CWE-478)"
    }
}