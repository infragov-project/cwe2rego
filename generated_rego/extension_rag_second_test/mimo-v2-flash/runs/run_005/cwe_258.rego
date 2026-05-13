package glitch

import data.glitch_lib

# Define credential patterns (case-insensitive regex)
credential_pattern := "(?i)(password|pwd|pass|token|secret|credential|auth|key|activationkey|connection_string|connection_uri|jdbc_url|dsn|root_password|admin_password)"

# Check if a value represents an empty password
is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty_value(value) {
    value.ir_type == "Null"
}

is_empty_value(value) {
    value.ir_type == "Undef"
}

# Check for empty password patterns in string values
contains_empty_password_pattern(value) {
    value.ir_type == "String"
    regex.match(".*pwd=;.*", value.value)
}

contains_empty_password_pattern(value) {
    value.ir_type == "String"
    regex.match(".*password=;.*", value.value)
}

# Main detection rule for variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    regex.match(credential_pattern, var.name)
    is_empty_value(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - An empty password allows unauthorized access. (CWE-258)"
    }
}

# Main detection rule for attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match(credential_pattern, attr.name)
    is_empty_value(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - An empty password allows unauthorized access. (CWE-258)"
    }
}

# Detection for string values containing empty password patterns
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    contains_empty_password_pattern(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password pattern found in configuration string - An empty password allows unauthorized access. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    contains_empty_password_pattern(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password pattern found in configuration string - An empty password allows unauthorized access. (CWE-258)"
    }
}

# Detection for nested hash values with empty passwords
Glitch_Analysis[result] {
    walk(input, [path, node])
    node.ir_type == "Hash"
    pair := node.value[_]
    key_expr := pair.key
    key_expr.ir_type == "String"
    regex.match(credential_pattern, key_expr.value)
    is_empty_value(pair.value)
    
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": sprintf("Empty password in nested configuration field '%s' - An empty password allows unauthorized access. (CWE-258)", [key_expr.value])
    }
}