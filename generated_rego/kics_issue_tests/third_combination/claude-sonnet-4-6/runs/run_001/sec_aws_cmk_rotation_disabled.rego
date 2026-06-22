package glitch

import data.glitch_lib

kms_key_type_pattern := "(?i).*(kms|cmk|master[_\\-]?key|customer[_\\-]?master[_\\-]?key|encryption[_\\-]?key|kms[_\\-]?key).*"

is_asymmetric_key(attrs) {
    attr := attrs[_]
    attr.name == "key_spec"
    attr.value.ir_type == "String"
    not regex.match("(?i).*symmetric.*", attr.value.value)
}

is_asymmetric_key(attrs) {
    attr := attrs[_]
    attr.name == "customer_master_key_spec"
    attr.value.ir_type == "String"
    not regex.match("(?i).*symmetric.*", attr.value.value)
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

    regex.match(kms_key_type_pattern, node.type)

    attrs := glitch_lib.all_attributes(node)
    not is_asymmetric_key(attrs)

    attr := attrs[_]
    attr.name == "enable_key_rotation"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_aws_cmk_rotation_disabled",
        "element": attr,
        "path": parent.path,
        "description": "CMK Key Rotation Not Enabled - Customer Master Keys should have automatic key rotation enabled to reduce the risk of key compromise. (CWE-321)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    regex.match(kms_key_type_pattern, node.type)

    attrs := glitch_lib.all_attributes(node)
    not is_asymmetric_key(attrs)
    not has_key_rotation_attr(attrs)

    result := {
        "type": "sec_aws_cmk_rotation_disabled",
        "element": node,
        "path": parent.path,
        "description": "CMK Key Rotation Not Enabled - Customer Master Keys should have automatic key rotation enabled to reduce the risk of key compromise. (CWE-321)"
    }
}