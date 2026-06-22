package glitch

import data.glitch_lib

elb_attr_names := {"load_balancers", "LoadBalancerNames", "load_balancer_names", "target_group_arns"}

asg_type_patterns := {"autoscaling_group", "auto_scaling_group", "ec2_asg", "autoscalinggroup"}

is_asg_type(type_str) {
    pattern := asg_type_patterns[_]
    glitch_lib.contains(type_str, pattern)
}

has_valid_elb_attr(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == elb_attr_names[_]
    attr.value.ir_type == "Array"
    count(attr.value.value) > 0
}

has_valid_elb_attr(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == elb_attr_names[_]
    attr.value.ir_type == "VariableReference"
}

has_valid_elb_attr(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == elb_attr_names[_]
    attr.value.ir_type == "FunctionCall"
}

has_valid_elb_attr(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == elb_attr_names[_]
    attr.value.ir_type == "String"
    attr.value.value != ""
}

any_elb_attr_present(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == elb_attr_names[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_asg_type(node.type)
    not has_valid_elb_attr(node)
    any_elb_attr_present(node)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == elb_attr_names[_]

    result := {
        "type": "sec_aws_asg_no_elbs",
        "element": attr,
        "path": parent.path,
        "description": "Auto Scaling Group missing ELB association - Auto Scaling Groups must be associated with at least one Elastic Load Balancer to ensure high availability and traffic distribution."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_asg_type(node.type)
    not has_valid_elb_attr(node)
    not any_elb_attr_present(node)

    result := {
        "type": "sec_aws_asg_no_elbs",
        "element": node,
        "path": parent.path,
        "description": "Auto Scaling Group missing ELB association - Auto Scaling Groups must be associated with at least one Elastic Load Balancer to ensure high availability and traffic distribution."
    }
}