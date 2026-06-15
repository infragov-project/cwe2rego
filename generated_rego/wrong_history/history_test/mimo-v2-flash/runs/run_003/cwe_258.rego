package glitch

import data.glitch_lib

password_keywords = {"password", "passwd", "pwd", "secret", "credential", "token"}

check_empty_password(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "VariableReference"
    # For variables, we need to check if they reference an empty string
    # This is a simplified check - in practice, we might need to trace the variable's value
    # For now, we'll skip variable references to avoid false positives
    false
}

check_connection_string(value) {
    value.ir_type == "String"
    regex.match(`(pwd|password)=;|pwd=&|password=&`, value.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check attribute name matches password keywords
    password_keywords[attr.name]
    
    # Check if value is empty password
    check_empty_password(attr.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    vars := glitch_lib.all_variables(node)
    var := vars[_]
    
    # Check variable name matches password keywords
    password_keywords[var.name]
    
    # Check if value is empty password
    check_empty_password(var.value)

    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for connection strings with empty password fields
    check_connection_string(attr.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Connection string with empty password field (CWE-258)"
    }
}