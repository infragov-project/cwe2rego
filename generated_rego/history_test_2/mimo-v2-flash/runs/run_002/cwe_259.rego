package glitch

import data.glitch_lib

password_keywords := {"password", "pass", "pwd", "secret", "key", "token", "credential", "admin_password", "db_password", "api_password", "auth_password"}

is_password_key(key) {
    lower_key := lower(key)
    password_keywords[_] == lower_key
}

is_hardcoded_password(value) {
    value.ir_type == "String"
    value.value != ""
    # Check if the value is not a variable reference or dynamic function call
    not glitch_lib.has_variable_reference(value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all attributes in the parent
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check if the attribute name indicates a password
    is_password_key(attr.name)
    
    # Check if the value is a hardcoded string
    is_hardcoded_password(attr.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid hard-coding credentials in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all variables in the parent
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if the variable name indicates a password
    is_password_key(var.name)
    
    # Check if the value is a hardcoded string
    is_hardcoded_password(var.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid hard-coding credentials in IaC scripts. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all atomic units
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check attributes within atomic units
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if the attribute name indicates a password
    is_password_key(attr.name)
    
    # Check if the value is a hardcoded string
    is_hardcoded_password(attr.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid hard-coding credentials in IaC scripts. (CWE-259)"
    }
}