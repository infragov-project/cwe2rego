package glitch

import data.glitch_lib
import future.keywords.in

password_identifiers := {"password"}

is_empty_password(value) {
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
    
    # Check Variables (e.g., Ansible, Puppet)
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    var_name := variable.name
    some identifier in password_identifiers
    regex.match(sprintf("(?i).*%s.*", [identifier]), var_name)
    is_empty_password(variable.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration file - Password field is set to an empty value. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Attributes (e.g., Chef, Puppet)
    attributes := glitch_lib.all_attributes(parent)
    attribute := attributes[_]
    attr_name := attribute.name
    some identifier in password_identifiers
    regex.match(sprintf("(?i).*%s.*", [identifier]), attr_name)
    is_empty_password(attribute.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attribute,
        "path": parent.path,
        "description": "Empty password in configuration file - Password field is set to an empty value. (CWE-258)"
    }
}