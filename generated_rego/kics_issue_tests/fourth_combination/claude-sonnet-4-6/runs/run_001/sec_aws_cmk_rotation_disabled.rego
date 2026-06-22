package glitch

import data.glitch_lib

kms_rotation_attr_names := {"enable_key_rotation", "rotation_enabled"}

is_kms_key_resource(node) {
    glitch_lib.contains(node.type, "kms")
}

has_rotation_attr(attrs) {
    attr := attrs[_]
    attr.name == kms_rotation_attr_names[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_kms_key_resource(node)
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == kms_rotation_attr_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_aws_cmk_rotation_disabled",
        "element": attr,
        "path": parent.path,
        "description": "KMS CMK Key Rotation Not Enabled - Key rotation should be enabled for KMS Customer Master Keys. (CWE-321)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_kms_key_resource(node)
    attrs := glitch_lib.all_attributes(node)
    not has_rotation_attr(attrs)

    result := {
        "type": "sec_aws_cmk_rotation_disabled",
        "element": node,
        "path": parent.path,
        "description": "KMS CMK Key Rotation Not Enabled - Key rotation should be enabled for KMS Customer Master Keys. (CWE-321)"
    }
}