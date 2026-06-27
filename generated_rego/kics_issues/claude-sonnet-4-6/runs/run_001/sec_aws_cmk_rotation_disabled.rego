package glitch

import data.glitch_lib

kms_keywords := {"kms", "key", "master_key", "customer_master_key", "cmk", "aws_kms_key", "kms_key"}

is_kms_resource(node) {
    glitch_lib.contains(node.type, kms_keywords[_])
}

has_rotation_attr(attrs) {
    attr := attrs[_]
    attr.name == "enable_key_rotation"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_kms_resource(node)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "enable_key_rotation"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_aws_cmk_rotation_disabled",
        "element": attr,
        "path": parent.path,
        "description": "AWS CMK Key Rotation Not Enabled - Automatic key rotation should be enabled for KMS Customer Master Keys to reduce the risk of key compromise. (CWE-324)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_kms_resource(node)

    attrs := glitch_lib.all_attributes(node)
    not has_rotation_attr(attrs)

    result := {
        "type": "sec_aws_cmk_rotation_disabled",
        "element": node,
        "path": parent.path,
        "description": "AWS CMK Key Rotation Not Enabled - Automatic key rotation should be enabled for KMS Customer Master Keys to reduce the risk of key compromise. (CWE-324)"
    }
}