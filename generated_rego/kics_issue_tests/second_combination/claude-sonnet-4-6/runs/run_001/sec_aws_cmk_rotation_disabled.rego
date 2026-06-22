package glitch

import data.glitch_lib

is_kms_resource(node) {
    regex.match("(?i).*(kms_key|kms|customer_master_key|cmk).*", node.type)
}

is_explicitly_disabled(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "enabled"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
}

has_rotation_attribute(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "enable_key_rotation"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_kms_resource(node)
    not is_explicitly_disabled(node)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "enable_key_rotation"
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_aws_cmk_rotation_disabled",
        "element": attr,
        "path": parent.path,
        "description": "KMS CMK key rotation not enabled - Customer Master Keys should have automatic key rotation enabled to reduce the risk of key compromise. (CWE-321)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_kms_resource(node)
    not is_explicitly_disabled(node)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "enable_key_rotation"
    attr.value.ir_type == "String"
    lower(attr.value.value) == "false"

    result := {
        "type": "sec_aws_cmk_rotation_disabled",
        "element": attr,
        "path": parent.path,
        "description": "KMS CMK key rotation not enabled - Customer Master Keys should have automatic key rotation enabled to reduce the risk of key compromise. (CWE-321)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_kms_resource(node)
    not is_explicitly_disabled(node)
    not has_rotation_attribute(node)

    result := {
        "type": "sec_aws_cmk_rotation_disabled",
        "element": node,
        "path": parent.path,
        "description": "KMS CMK key rotation not enabled - Customer Master Keys should have automatic key rotation enabled to reduce the risk of key compromise. (CWE-321)"
    }
}