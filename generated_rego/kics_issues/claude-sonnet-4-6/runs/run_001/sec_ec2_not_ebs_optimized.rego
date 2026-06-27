package glitch

import data.glitch_lib

ec2_type_keywords := {"instance", "ec2", "virtual_machine", "compute_instance"}
ebs_attr_keywords := {"ebs_optimized", "ebs_optimization", "optimized"}

is_ec2_resource(node) {
    glitch_lib.contains(node.type, ec2_type_keywords[_])
}

has_ebs_optimization_attr(attrs) {
    attr := attrs[_]
    glitch_lib.contains(attr.name, ebs_attr_keywords[_])
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_ec2_resource(node)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    glitch_lib.contains(attr.name, ebs_attr_keywords[_])

    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_ec2_not_ebs_optimized",
        "element": attr,
        "path": parent.path,
        "description": "EC2 Instance EBS Optimization Not Enabled - EBS optimization should be enabled to avoid performance degradation due to shared bandwidth between EBS I/O and other network traffic."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_ec2_resource(node)

    attrs := glitch_lib.all_attributes(node)
    not has_ebs_optimization_attr(attrs)

    result := {
        "type": "sec_ec2_not_ebs_optimized",
        "element": node,
        "path": parent.path,
        "description": "EC2 Instance EBS Optimization Not Enabled - EBS optimization should be enabled to avoid performance degradation due to shared bandwidth between EBS I/O and other network traffic."
    }
}