package glitch

import data.glitch_lib

password_keywords := {"password", "secret", "credential", "token", "key", "auth", "passphrase", "admin_password", "root_password", "login_credentials", "auth_secrets", "connection_string", "uri", "endpoint", "api_key", "database_password", "service_account_key", "default_password", "initial_password"}

check_password_value(value) {
    value.ir_type == "String"
    value.value != ""
    not startswith(value.value, "var.")
    not startswith(value.value, "${")
    not startswith(value.value, "{{")
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    some kw in password_keywords
    attr.name == kw

    check_password_value(attr.value)

    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Credentials embedded directly in code/configurations. (CWE-259)"
    }
}