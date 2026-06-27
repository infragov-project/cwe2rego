package glitch

import data.glitch_lib

is_asg_type(t) {
    regex.match("(?i).*(auto.?scaling.?group|ec2.?asg).*", t)
}

is_lb_or_tg_attr(name) {
    regex.match("(?i).*(load.?balancer|elb.?name|classic.?load|target.?group).*", name)
}

attr_is_empty_array(attr) {
    attr.value.ir_type == "Array"
    count(attr.value.value) == 0
}

has_valid_lb_or_tg(node) {
    attr := node.attributes[_]
    is_lb_or_tg_attr(attr.name)
    not attr_is_empty_array(attr)
}

lb_or_tg_attr_exists(node) {
    attr := node.attributes[_]
    is_lb_or_tg_attr(attr.name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_asg_type(node.type)
    not has_valid_lb_or_tg(node)

    attr := node.attributes[_]
    is_lb_or_tg_attr(attr.name)
    attr_is_empty_array(attr)

    result := {
        "type": "sec_aws_asg_no_elbs",
        "element": attr,
        "path": parent.path,
        "description": "Auto Scaling Group without ELB association - Auto Scaling Groups should be associated with at least one Elastic Load Balancer to ensure high availability and traffic distribution."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_asg_type(node.type)
    not has_valid_lb_or_tg(node)
    not lb_or_tg_attr_exists(node)

    result := {
        "type": "sec_aws_asg_no_elbs",
        "element": node,
        "path": parent.path,
        "description": "Auto Scaling Group without ELB association - Auto Scaling Groups should be associated with at least one Elastic Load Balancer to ensure high availability and traffic distribution."
    }
}