package glitch

import data.glitch_lib

lb_attr_names := {"load_balancers", "LoadBalancerNames", "load_balancer_names", "elb_names", "target_group_arns"}

is_asg_type(t) {
    regex.match("(?i).*(autoscal|auto_scaling|_asg).*", t)
}

is_valid_value(value) {
    value.ir_type == "Array"
    count(value.value) > 0
}

is_valid_value(value) {
    value.ir_type == "String"
    value.value != ""
}

is_valid_value(value) {
    value.ir_type == "VariableReference"
}

is_valid_value(value) {
    value.ir_type == "FunctionCall"
}

has_valid_lb_attr(attrs) {
    attr := attrs[_]
    lb_attr_names[attr.name]
    is_valid_value(attr.value)
}

any_lb_attr_exists(attrs) {
    attr := attrs[_]
    lb_attr_names[attr.name]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_asg_type(node.type)
    attrs := glitch_lib.all_attributes(node)
    not has_valid_lb_attr(attrs)
    any_lb_attr_exists(attrs)
    attr := attrs[_]
    lb_attr_names[attr.name]
    not is_valid_value(attr.value)
    result := {
        "type": "sec_aws_asg_no_elbs",
        "element": attr,
        "path": parent.path,
        "description": "Auto Scaling Group missing ELB association - Auto Scaling Groups should be associated with a Load Balancer for high availability and proper traffic distribution."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_asg_type(node.type)
    attrs := glitch_lib.all_attributes(node)
    not has_valid_lb_attr(attrs)
    not any_lb_attr_exists(attrs)
    result := {
        "type": "sec_aws_asg_no_elbs",
        "element": node,
        "path": parent.path,
        "description": "Auto Scaling Group missing ELB association - Auto Scaling Groups should be associated with a Load Balancer for high availability and proper traffic distribution."
    }
}