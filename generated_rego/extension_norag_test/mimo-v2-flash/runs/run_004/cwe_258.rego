package glitch

import data.glitch_lib

password_keywords := {"password", "pwd", "secret", "token", "key", "credential", "passphrase", "auth_key", "api_key", "secret_key", "activationkey"}

check_password_name(name) {
    lower_name := lower(name)
    keyword := password_keywords[_]
    contains(lower_name, keyword)
}

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty_value(value) {
    value.ir_type == "Null"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables (for Ansible, Chef, and Puppet parameters)
    variable := glitch_lib.all_variables(parent)[_]
    check_password_name(variable.name)
    is_empty_value(variable.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password variable - Password variables should not be left empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes (for resource attributes in Ansible, Chef, and Puppet)
    attribute := glitch_lib.all_attributes(parent)[_]
    check_password_name(attribute.name)
    is_empty_value(attribute.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attribute,
        "path": parent.path,
        "description": "Empty password attribute - Password attributes should not be left empty. (CWE-258)"
    }
}