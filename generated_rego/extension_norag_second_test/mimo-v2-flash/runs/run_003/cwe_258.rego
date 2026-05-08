package glitch

import data.glitch_lib

password_keywords := {"password", "pwd", "passphrase", "secret", "credential", "auth", "key"}

is_password_field(name) {
    some keyword in password_keywords
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
    is_password_field(variable.name)
    is_empty_value(variable.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration file - The password field is empty, allowing unauthorized access. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attributes := glitch_lib.all_attributes(parent)
    attribute := attributes[_]
    is_password_field(attribute.name)
    is_empty_value(attribute.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attribute,
        "path": parent.path,
        "description": "Empty password in configuration file - The password field is empty, allowing unauthorized access. (CWE-258)"
    }
}