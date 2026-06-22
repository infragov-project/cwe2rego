package glitch

import data.glitch_lib

lb_attr_names := {"load_balancer_names", "LoadBalancerNames", "load_balancers", "target_group_arns"}

is_asg_type(t) {
    regex.match("(?i).*(autoscal|auto.scal|_asg$|\\.asg$)", t)
}

is_empty_lb_value(value) {
    value.ir_type == "Null"
}

is_empty_lb_value(value) {
    value.ir_type == "Undef"
}

is_empty_lb_value(value) {
    value.ir_type == "Array"
    count(value.value) == 0
}

is_empty_lb_value(value) {
    value.ir_type == "String"
    value.value == ""
}

has_valid_lb_attr(attrs) {
    attr := attrs[_]
    attr.name == lb_attr_names[_]
    not is_empty_lb_value(attr.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_asg_type(node.type)
    attrs := glitch_lib.all_attributes(node)
    not has_valid_lb_attr(attrs)
    result := {
        "type": "sec_aws_asg_no_elbs",
        "element": node,
        "path": parent.path,
        "description": "Auto Scaling Group Missing ELB Association - Auto Scaling Groups should have associated Load Balancers for proper traffic distribution and health checks."
    }
}