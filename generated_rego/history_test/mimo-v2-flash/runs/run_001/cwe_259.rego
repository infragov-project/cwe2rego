package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    password_keywords := {"password", "secret", "token", "api_key", "credential", "auth", "passwd", "admin_password", "api_token", "shared_access_key"}
    attr.name == password_keywords[_]

    attr.value.ir_type == "String"
    attr.value.value != ""

    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Hard-coded passwords in IaC scripts violate secure storage practices. (CWE-259)"
    }
}