package glitch

import data.glitch_lib

hardcoded_password_keywords := {"password", "pass", "pwd", "secret", "token"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name in hardcoded_password_keywords
    attr.value.ir_type == "String"
    not regex.match("^[a-zA-Z0-9+/]+={0,2}$", attr.value.value)

    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded password detected in IaC script - Avoid storing passwords directly in code. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name in hardcoded_password_keywords
    attr.value.ir_type == "String"
    regex.match("^[a-zA-Z0-9+/]+={0,2}$", attr.value.value)

    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded Base64 encoded password detected in IaC script - Avoid storing passwords directly in code. (CWE-259)"
    }
}