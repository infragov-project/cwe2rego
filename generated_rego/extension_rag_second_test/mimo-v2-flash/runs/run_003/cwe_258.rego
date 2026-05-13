package glitch

import data.glitch_lib

credential_keywords := {"password", "pwd", "secret", "token", "key", "credential", "auth", "passphrase", "secret_key", "api_key"}

check_credential_field(name) {
    lower_name := lower(name)
    some keyword in credential_keywords
    contains(lower_name, keyword)
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
    
    var := glitch_lib.all_variables(parent)[_]
    check_credential_field(var.name)
    is_empty_value(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attr := glitch_lib.all_attributes(parent)[_]
    check_credential_field(attr.name)
    is_empty_value(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty. (CWE-258)"
    }
}