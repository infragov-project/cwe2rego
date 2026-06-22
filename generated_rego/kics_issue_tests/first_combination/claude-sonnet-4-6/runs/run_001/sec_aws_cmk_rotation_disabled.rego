package glitch

import data.glitch_lib

is_kms_resource(node) {
    glitch_lib.contains(node.type, "kms")
}

rotation_disabled(value) {
    value.ir_type == "Boolean"
    value.value == false
}

rotation_disabled(value) {
    value.ir_type == "Null"
}

has_key_rotation_attr(attrs) {
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
    rotation_disabled(attr.value)
    result := {
        "type": "sec_aws_cmk_rotation_disabled",
        "element": attr,
        "path": parent.path,
        "description": "CMK Key Rotation Not Enabled - Customer Master Keys should have automatic key rotation explicitly enabled to reduce the risk of key compromise over time. (CWE-320)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_kms_resource(node)
    attrs := glitch_lib.all_attributes(node)
    not has_key_rotation_attr(attrs)
    result := {
        "type": "sec_aws_cmk_rotation_disabled",
        "element": node,
        "path": parent.path,
        "description": "CMK Key Rotation Not Enabled - Customer Master Keys are missing the enable_key_rotation attribute, which must be explicitly set to true. (CWE-320)"
    }
}