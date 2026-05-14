package glitch

import data.glitch_lib

password_indicators := {
    "password",
    "pwd",
    "secret",
    "passphrase",
    "admin_password",
    "db_password",
    "api_key",
    "activationkey",
    "ssh_password",
    "proxy_password",
    "mysql_password"
}

check_empty_password(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    all_vars := glitch_lib.all_variables(parent)
    var := all_vars[_]

    name_lower := lower(var.name)
    indicator := password_indicators[_]
    contains(name_lower, indicator)

    check_empty_password(var.value)

    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password configuration detected - Password fields should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]

    name_lower := lower(attr.name)
    indicator := password_indicators[_]
    contains(name_lower, indicator)

    check_empty_password(attr.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password configuration detected - Password fields should not be empty or null. (CWE-258)"
    }
}