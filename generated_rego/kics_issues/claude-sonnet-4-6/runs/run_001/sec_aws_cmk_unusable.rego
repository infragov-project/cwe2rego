package glitch

import data.glitch_lib

kms_resource_types := {"aws_kms_key", "aws_kms", "kms_key"}
enabled_attrs := {"enabled", "is_enabled"}
pending_attrs := {"pending_window", "pending_window_in_days", "deletion_window_in_days"}

is_kms_resource(node_type) {
    glitch_lib.contains(node_type, kms_resource_types[_])
}

is_disabled_value(value) {
    value.ir_type == "Boolean"
    value.value == false
}

is_disabled_value(value) {
    value.ir_type == "Integer"
    value.value == 0
}

is_disabled_value(value) {
    value.ir_type == "String"
    lower(value.value) == "false"
}

is_disabled_value(value) {
    value.ir_type == "String"
    lower(value.value) == "no"
}

is_disabled_value(value) {
    value.ir_type == "String"
    value.value == "0"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_kms_resource(node.type)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == enabled_attrs[_]
    is_disabled_value(attr.value)

    result := {
        "type": "sec_aws_cmk_unusable",
        "element": attr,
        "path": parent.path,
        "description": "AWS KMS Customer Master Key (CMK) is disabled - KMS keys should be enabled and not scheduled for deletion to ensure encryption operations are not disrupted."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_kms_resource(node.type)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == pending_attrs[_]

    result := {
        "type": "sec_aws_cmk_unusable",
        "element": attr,
        "path": parent.path,
        "description": "AWS KMS Customer Master Key (CMK) is scheduled for deletion - KMS keys should not be scheduled for deletion to ensure encryption operations are not disrupted."
    }
}