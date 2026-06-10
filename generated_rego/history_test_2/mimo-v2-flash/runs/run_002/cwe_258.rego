package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    password_fields := {"password", "pwd", "passphrase", "secret", "admin_password", "master_password", "initial_password"}
    attr.name == password_fields[_]

    value := attr.value
    value.ir_type == "String"
    regex.match("^(\\s*)$", value.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    password_fields := {"password", "pwd", "passphrase", "secret", "admin_password", "master_password", "initial_password"}
    attr.name == password_fields[_]

    value := attr.value
    value.ir_type == "Null"

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty. (CWE-258)"
    }
}