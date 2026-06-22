package glitch

import data.glitch_lib

kms_keywords := ["kms", "key", "customer_master_key", "cmk", "master_key"]

enabled_attr_names := {"enabled", "is_enabled"}

deletion_attr_names := {"deletion_window_in_days", "pending_window", "pending_window_in_days"}

is_kms_resource(node) {
    glitch_lib.contains(node.type, kms_keywords[_])
}

is_disabled(attr) {
    attr.value.ir_type == "Boolean"
    attr.value.value == false
}

is_disabled(attr) {
    attr.value.ir_type == "String"
    lower(attr.value.value) == "false"
}

is_disabled(attr) {
    attr.value.ir_type == "String"
    lower(attr.value.value) == "no"
}

is_disabled(attr) {
    attr.value.ir_type == "Integer"
    attr.value.value == 0
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_kms_resource(node)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == enabled_attr_names[_]
    is_disabled(attr)

    result := {
        "type": "sec_aws_cmk_unusable",
        "element": attr,
        "path": parent.path,
        "description": "KMS Customer Master Key is disabled - Disabled cryptographic keys may represent orphaned or improperly lifecycle-managed resources."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_kms_resource(node)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == deletion_attr_names[_]
    attr.value.ir_type == "Integer"

    result := {
        "type": "sec_aws_cmk_unusable",
        "element": attr,
        "path": parent.path,
        "description": "KMS Customer Master Key is scheduled for deletion - Keys with a deletion window defined indicate the key is being decommissioned and may no longer be available for cryptographic operations."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    is_kms_resource(node)

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "key_state"
    attr.value.ir_type == "String"
    lower(attr.value.value) == {"disabled", "pendingdeletion"}[_]

    result := {
        "type": "sec_aws_cmk_unusable",
        "element": attr,
        "path": parent.path,
        "description": "KMS Customer Master Key is in an unusable state - Keys that are disabled or pending deletion represent a security and operational risk due to improper key lifecycle management."
    }
}