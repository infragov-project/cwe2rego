package glitch

import data.glitch_lib

import future.keywords.in

password_fields := {"password", "pwd", "pass", "secret", "key", "token", "credential", "auth", "secret_key", "api_key", "access_key"}

is_empty(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty(value) {
    value.ir_type == "Null"
}

is_empty(value) {
    value.ir_type == "Undef"
}

is_empty(value) {
    value.ir_type == "Array"
    count(value.value) == 0
}

is_empty(value) {
    value.ir_type == "Hash"
    count(value.value) == 0
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    lower_name := lower(variable.name)
    some pattern in password_fields
    contains(lower_name, pattern)
    is_empty(variable.value)
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration file - This may allow unauthorized access. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attribute := attributes[_]
    lower_name := lower(attribute.name)
    some pattern in password_fields
    contains(lower_name, pattern)
    is_empty(attribute.value)
    result := {
        "type": "sec_empty_pass",
        "element": attribute,
        "path": parent.path,
        "description": "Empty password in configuration file - This may allow unauthorized access. (CWE-258)"
    }
}