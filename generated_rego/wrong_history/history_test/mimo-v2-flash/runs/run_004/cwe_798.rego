package glitch

import data.glitch_lib

sensitive_attributes := {
    "password",
    "secret",
    "token",
    "api_key",
    "apiKey",
    "private_key",
    "privateKey",
    "auth",
    "credential",
    "key_material",
    "content",
    "user_data",
    "environment_variables",
    "env",
    "default"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    sensitive_attributes[attr.name]

    attr.value.ir_type == "String"
    attr.value.value != ""

    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential detected in attribute. (CWE-798)"
    }
}