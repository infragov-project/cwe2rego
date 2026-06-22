package glitch

import data.glitch_lib

kms_types := {"aws_kms_key", "aws_kms", "kms_key", "kms", "customer_master_key", "cmk", "key_management_service"}

enabled_attr_names := {"is_enabled", "enabled", "key_enabled", "enable", "state", "key_state"}

deletion_attr_names := {"pending_window", "deletion_window_in_days", "pending_window_in_days", "pending_deletion", "deletion_period", "key_deletion_window"}

is_kms_resource(node) {
    glitch_lib.contains(node.type, kms_types[_])
}

is_disabled(attr) {
    attr.value.ir_type == "Boolean"
    attr.value.value == false
}

is_disabled(attr) {
    attr.value.ir_type == "String"
    regex.match("(?i)^(false|disabled|inactive)$", attr.value.value)
}

has_enabled_attribute(attrs) {
    attr := attrs[_]
    attr.name == enabled_attr_names[_]
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
        "description": "AWS KMS Customer Master Key (CMK) is disabled - Disabled CMKs will cause encryption/decryption operations to fail for dependent services."
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    is_kms_resource(node)

    attrs := glitch_lib.all_attributes(node)
    not has_enabled_attribute(attrs)

    result := {
        "type": "sec_aws_cmk_unusable",
        "element": node,
        "path": parent.path,
        "description": "AWS KMS Customer Master Key (CMK) lacks an explicit enabled state - CMKs should explicitly define their enabled state to prevent unintended access failures."
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

    result := {
        "type": "sec_aws_cmk_unusable",
        "element": attr,
        "path": parent.path,
        "description": "AWS KMS Customer Master Key (CMK) is scheduled for deletion - CMKs with a deletion window will be permanently deleted, causing irreversible data loss."
    }
}