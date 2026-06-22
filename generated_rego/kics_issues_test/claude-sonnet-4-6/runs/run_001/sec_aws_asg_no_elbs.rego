package glitch

import data.glitch_lib

is_asg_type(type_str) {
    regex.match("(?i).*(autoscaling|auto_scaling|ec2_asg).*", type_str)
}

elb_attr_name_matches(name) {
    regex.match("(?i)(load_?balancer_?names?|load_?balancers?|elb_?names?|target_?group_?arns?)", name)
}

has_valid_array_items(arr) {
    item := arr.value[_]
    item.ir_type == "String"
    item.value != ""
}

has_valid_array_items(arr) {
    item := arr.value[_]
    item.ir_type == "VariableReference"
}

has_valid_array_items(arr) {
    item := arr.value[_]
    item.ir_type == "FunctionCall"
}

elb_attr_valid_value(value) {
    value.ir_type == "Array"
    has_valid_array_items(value)
}

elb_attr_valid_value(value) {
    value.ir_type == "String"
    value.value != ""
}

elb_attr_valid_value(value) {
    value.ir_type == "VariableReference"
}

any_elb_attr(attrs) {
    attr := attrs[_]
    elb_attr_name_matches(attr.name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_asg_type(node.type)
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    elb_attr_name_matches(attr.name)
    not elb_attr_valid_value(attr.value)

    result := {
        "type": "sec_aws_asg_no_elbs",
        "element": attr,
        "path": parent.path,
        "description": "Auto Scaling Group missing ELB association - ASGs should be associated with a Load Balancer for proper traffic distribution and health checks."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_asg_type(node.type)
    attrs := glitch_lib.all_attributes(node)
    not any_elb_attr(attrs)

    result := {
        "type": "sec_aws_asg_no_elbs",
        "element": node,
        "path": parent.path,
        "description": "Auto Scaling Group missing ELB association - ASGs should be associated with a Load Balancer for proper traffic distribution and health checks."
    }
}