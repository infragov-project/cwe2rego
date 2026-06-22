package glitch

import data.glitch_lib

lb_attr_names := {"load_balancers", "LoadBalancerNames", "load_balancer_names"}

is_asg_resource(type_str) {
    glitch_lib.contains(type_str, "autoscaling_group")
}

is_asg_resource(type_str) {
    glitch_lib.contains(type_str, "auto_scaling_group")
}

is_asg_resource(type_str) {
    regex.match("(?i)(.*_asg$|^asg$|^asg_.*)", type_str)
}

is_empty_lb_value(value) {
    value.ir_type == "Array"
    count(value.value) == 0
}

is_empty_lb_value(value) {
    value.ir_type == "Null"
}

is_empty_lb_value(value) {
    value.ir_type == "Undef"
}

has_any_lb_attr(node) {
    walk(node, [_, attr])
    attr.ir_type == "Attribute"
    attr.name == lb_attr_names[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_asg_resource(node.type)
    walk(node, [_, attr])
    attr.ir_type == "Attribute"
    attr.name == lb_attr_names[_]
    is_empty_lb_value(attr.value)
    result := {
        "type": "sec_aws_asg_no_elbs",
        "element": attr,
        "path": parent.path,
        "description": "ASG without associated ELB - An Auto Scaling Group is defined without an Elastic Load Balancer, reducing fault tolerance and high availability."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_asg_resource(node.type)
    not has_any_lb_attr(node)
    result := {
        "type": "sec_aws_asg_no_elbs",
        "element": node,
        "path": parent.path,
        "description": "ASG without associated ELB - An Auto Scaling Group is defined without an Elastic Load Balancer, reducing fault tolerance and high availability."
    }
}