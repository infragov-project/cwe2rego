package glitch

import data.glitch_lib

is_load_balancer_resource(node_type) {
    regex.match("(?i).*(alb|load_balancer|_lb).*", node_type)
}

is_application_lb(attrs) {
    attr := attrs[_]
    attr.name == "load_balancer_type"
    attr.value.ir_type == "String"
    attr.value.value == "application"
}

has_attribute_named(attrs, name) {
    attr := attrs[_]
    attr.name == name
}

in_scope_for_alb(attrs) {
    is_application_lb(attrs)
}

in_scope_for_alb(attrs) {
    not has_attribute_named(attrs, "load_balancer_type")
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_load_balancer_resource(node.type)
    attrs := glitch_lib.all_attributes(node)
    in_scope_for_alb(attrs)

    attr := attrs[_]
    attr.name == "drop_invalid_header_fields"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_alb_drop_invalid_headers",
        "element": attr,
        "path": parent.path,
        "description": "ALB not dropping invalid HTTP header fields - Application Load Balancers should be configured to drop invalid HTTP header fields to prevent header injection, request smuggling, and cache poisoning attacks."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_load_balancer_resource(node.type)
    attrs := glitch_lib.all_attributes(node)
    in_scope_for_alb(attrs)

    not has_attribute_named(attrs, "drop_invalid_header_fields")

    result := {
        "type": "sec_alb_drop_invalid_headers",
        "element": node,
        "path": parent.path,
        "description": "ALB not dropping invalid HTTP header fields - Application Load Balancers should be configured to drop invalid HTTP header fields to prevent header injection, request smuggling, and cache poisoning attacks."
    }
}