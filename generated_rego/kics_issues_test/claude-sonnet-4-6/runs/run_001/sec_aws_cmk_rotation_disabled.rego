package glitch

import data.glitch_lib

rotation_attr_name(name) {
    regex.match("(?i).*(enable_key_rotation|rotation_enabled).*", name)
}

rotation_attr_false(attr) {
    rotation_attr_name(attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false
}

rotation_attr_false(attr) {
    rotation_attr_name(attr.name)
    attr.value.ir_type == "String"
    lower(attr.value.value) == "false"
}

rotation_attr_present(attrs) {
    attr := attrs[_]
    rotation_attr_name(attr.name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    regex.match("(?i).*kms.*", node.type)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    rotation_attr_false(attr)

    result := {
        "type": "sec_aws_cmk_rotation_disabled",
        "element": attr,
        "path": parent.path,
        "description": "KMS CMK Key Rotation Not Enabled - Automatic key rotation should be enabled for KMS Customer Master Keys to reduce the risk of key compromise. (CWE-326)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    regex.match("(?i).*kms.*", node.type)

    attrs := glitch_lib.all_attributes(node)
    not rotation_attr_present(attrs)

    result := {
        "type": "sec_aws_cmk_rotation_disabled",
        "element": node,
        "path": parent.path,
        "description": "KMS CMK Key Rotation Not Enabled - Automatic key rotation should be enabled for KMS Customer Master Keys to reduce the risk of key compromise. (CWE-326)"
    }
}