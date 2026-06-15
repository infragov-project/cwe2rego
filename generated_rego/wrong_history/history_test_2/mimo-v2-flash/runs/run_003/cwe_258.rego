package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables in UnitBlock (for Ansible, Chef, Puppet)
    variable := parent.variables[_]
    
    # Check if variable name contains authentication-related keywords
    auth_keywords := {"password", "secret", "passphrase", "auth_key", "token", "ssh_password", "pwd", "db_password"}
    name_lower := lower(variable.name)
    some keyword in auth_keywords
    contains(name_lower, keyword)
    
    # Check if value is empty string or null
    variable.value.ir_type == "String"
    variable.value.value == ""
    
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables in UnitBlock (for Chef with Null values)
    variable := parent.variables[_]
    
    # Check if variable name contains authentication-related keywords
    auth_keywords := {"password", "secret", "passphrase", "auth_key", "token", "ssh_password", "pwd", "db_password"}
    name_lower := lower(variable.name)
    some keyword in auth_keywords
    contains(name_lower, keyword)
    
    # Check if value is null
    variable.value.ir_type == "Null"
    
    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in atomic units (for resources with password attributes)
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if attribute name contains authentication-related keywords
    auth_keywords := {"password", "secret", "passphrase", "auth_key", "token", "ssh_password", "pwd", "db_password"}
    name_lower := lower(attr.name)
    some keyword in auth_keywords
    contains(name_lower, keyword)
    
    # Check if value is empty string
    attr.value.ir_type == "String"
    attr.value.value == ""
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in atomic units (for resources with password attributes and Null values)
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if attribute name contains authentication-related keywords
    auth_keywords := {"password", "secret", "passphrase", "auth_key", "token", "ssh_password", "pwd", "db_password"}
    name_lower := lower(attr.name)
    some keyword in auth_keywords
    contains(name_lower, keyword)
    
    # Check if value is null
    attr.value.ir_type == "Null"
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty. (CWE-258)"
    }
}