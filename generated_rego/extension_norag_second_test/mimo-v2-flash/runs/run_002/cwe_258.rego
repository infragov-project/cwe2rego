package glitch

import data.glitch_lib

# Define password-related keywords (excluding "token" and "credentials" to reduce false positives)
password_keywords := {"password", "pwd", "pass", "passwd", "secret", "key"}

# Helper function to check if a name contains any password keyword
any_password_keyword(name) {
    some kw in password_keywords
    glitch_lib.contains(name, kw)
}

# Helper function to check if a value is considered an empty password
empty_password_value(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

# Rule for Variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_vars := glitch_lib.all_variables(parent)
    var := all_vars[_]
    any_password_keyword(var.name)
    empty_password_value(var.value)
    
    # Exclude false positives for cache-related keys
    not glitch_lib.contains(var.name, "cache")
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be set to an empty string. (CWE-258)"
    }
}

# Rule for Attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    any_password_keyword(attr.name)
    empty_password_value(attr.value)
    
    # Exclude false positives for cache-related keys
    not glitch_lib.contains(attr.name, "cache")
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be set to an empty string. (CWE-258)"
    }
}