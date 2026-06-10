package glitch

import data.glitch_lib
import future.keywords.in

sensitive_patterns := {"password", "pass", "pwd", "secret", "api_key", "token", "secret_key", "admin_password", "root_password", "initial_password", "bootstrap_password"}

is_sensitive_name(name) {
    some pattern in sensitive_patterns
    glitch_lib.contains(name, pattern)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all attributes and variables from the parent
    attributes := glitch_lib.all_attributes(parent)
    variables := glitch_lib.all_variables(parent)
    
    # Combine them into one set
    key_values := attributes | variables
    
    key_value := key_values[_]
    is_sensitive_name(key_value.name)
    
    # Check that the value is a string literal (and not a variable reference)
    key_value.value.ir_type == "String"
    
    result := {
        "type": "sec_hard_pass",
        "element": key_value,
        "path": parent.path,
        "description": "Use of hard-coded password - Avoid using hard-coded passwords in configuration. (CWE-259)"
    }
}