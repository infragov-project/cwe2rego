package glitch

import data.glitch_lib

password_keywords := {"password", "pwd", "secret", "passwd", "admin_password", "db_password", "connection_string", "credential", "api_key", "key", "token", "auth"}

contains_password_keyword(name) {
    some keyword
    password_keywords[keyword]
    regex.match(sprintf("(?i).*%s.*", [keyword]), name)
}

is_empty_value(value) {
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
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    contains_password_keyword(variable.name)
    is_empty_value(variable.value)
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration file (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attribute := attributes[_]
    contains_password_keyword(attribute.name)
    is_empty_value(attribute.value)
    result := {
        "type": "sec_empty_pass",
        "element": attribute,
        "path": parent.path,
        "description": "Empty password in configuration file (CWE-258)"
    }
}