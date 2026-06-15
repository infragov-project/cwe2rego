package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables in the unit block
    variable := parent.variables[_]
    
    # Check if variable name matches password-related keywords
    password_keywords := {"password", "passwd", "pwd", "secret", "credential", "token", "api_key", "auth_token"}
    contains_lower := lower(variable.name)
    some keyword in password_keywords
    regex.match(sprintf(".*%s.*", [keyword]), contains_lower)
    
    # Check if value is empty string or null
    variable.value.ir_type == "String"
    variable.value.value == ""
    
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration file - Passwords should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables in the unit block
    variable := parent.variables[_]
    
    # Check if variable name matches password-related keywords
    password_keywords := {"password", "passwd", "pwd", "secret", "credential", "token", "api_key", "auth_token"}
    contains_lower := lower(variable.name)
    some keyword in password_keywords
    regex.match(sprintf(".*%s.*", [keyword]), contains_lower)
    
    # Check if value is null
    variable.value.ir_type == "Null"
    
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration file - Passwords should not be empty. (CWE-258)"
    }
}