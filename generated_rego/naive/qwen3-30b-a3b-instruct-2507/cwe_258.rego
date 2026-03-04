package glitch

import data.glitch_lib

credential_fields := {"password", "pwd", "secret", "token", "auth", "access_key", "secret_key", "connection_string", "credentials", "login", "uid", "username"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    lower_name := to_lower(attr.name)
    contains(credential_fields, lower_name)

    value := attr.value
    (value.ir_type == "String" and value.value == "") or
    (value.ir_type == "Null") or
    (value.ir_type == "String" and trim(value.value) == "")

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password detected in configuration file. This is a common security vulnerability where credentials are set to an empty string, leading to potential unauthorized access. (CWE-258)"
    }
}