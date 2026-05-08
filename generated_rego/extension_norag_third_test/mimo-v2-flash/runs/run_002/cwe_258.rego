package glitch

import data.glitch_lib

password_keywords := {"password", "passwd", "pwd", "secret", "key", "token", "credential"}

check_empty_value(value) {
    value.ir_type == "String"
    regex.match("^\\s*$", value.value)
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

check_password_field(node) {
    node.name != ""
    some keyword
    password_keywords[keyword]
    contains(lower(node.name), keyword)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    check_password_field(variable)
    check_empty_value(variable.value)
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password value detected - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attribute := attributes[_]
    check_password_field(attribute)
    check_empty_value(attribute.value)
    result := {
        "type": "sec_empty_pass",
        "element": attribute,
        "path": parent.path,
        "description": "Empty password value detected - Password fields should not be empty. (CWE-258)"
    }
}