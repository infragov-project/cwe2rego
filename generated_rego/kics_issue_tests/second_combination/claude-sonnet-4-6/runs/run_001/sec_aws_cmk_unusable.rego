package glitch

import data.glitch_lib

kms_keywords := {"kms", "customer_master_key", "cmk", "kms_key", "key_management", "master_key"}
deletion_names := {"pending_window", "deletion_window_in_days"}
enabled_names := {"enabled", "is_enabled"}

is_kms_resource(node) {
    glitch_lib.contains(node.type, kms_keywords[_])
}

Glitch_Analysis[result] {
    walk(input, [_, parent])
    parent.ir_type == "UnitBlock"
    parent.path != ""
    node := glitch_lib.all_atomic_units(parent)[_]
    is_kms_resource(node)
    attr := glitch_lib.all_attributes(node)[_]
    attr.name == deletion_names[_]
    result := {
        "type": "sec_aws_cmk_unusable",
        "element": attr,
        "path": parent.path,
        "description": "KMS CMK is scheduled for deletion - a deletion window attribute is defined."
    }
}

Glitch_Analysis[result] {
    walk(input, [_, parent])
    parent.ir_type == "UnitBlock"
    parent.path != ""
    node := glitch_lib.all_atomic_units(parent)[_]
    is_kms_resource(node)
    attr := glitch_lib.all_attributes(node)[_]
    attr.name == enabled_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_aws_cmk_unusable",
        "element": attr,
        "path": parent.path,
        "description": "KMS CMK is not usable - the key is explicitly disabled."
    }
}