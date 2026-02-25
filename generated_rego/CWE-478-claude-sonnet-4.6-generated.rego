package glitch

import data.glitch_lib

lb_listener_types := {"aws_lb_listener", "aws_alb_listener"}

provisioner_types := {"local-exec", "remote-exec"}

has_default_in_chain(stmt) {
    walk(stmt, [_, node])
    node.ir_type == "ConditionalStatement"
    node.is_default == true
}

has_attr_named(node, name) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    lower(attr.name) == name
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    stmt := conditions[_]
    stmt.is_top == true
    stmt.type == "SWITCH"
    not has_default_in_chain(stmt)
    result := {
        "type": "sec_no_default_switch",
        "element": stmt,
        "path": parent.path,
        "description": "Missing default case in switch/case/match statement - Conditional expressions should include a catch-all default case to handle unexpected inputs. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "FunctionCall"
    lower(node.name) == "lookup"
    count(node.args) < 3
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default value in lookup() function call - Map access operations should provide a default fallback to avoid unhandled missing key states. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == lb_listener_types[_]
    not has_attr_named(node, "default_action")
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing default_action in load balancer listener - Listener rules should define a default_action to handle all unmatched requests. (CWE-478)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == provisioner_types[_]
    not has_attr_named(node, "on_failure")
    result := {
        "type": "sec_no_default_switch",
        "element": node,
        "path": parent.path,
        "description": "Missing on_failure handler in provisioner block - Provisioners should specify on_failure behavior to handle unexpected execution states. (CWE-478)"
    }
}