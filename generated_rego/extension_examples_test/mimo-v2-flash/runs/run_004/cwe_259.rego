package glitch

import data.glitch_lib

# Define suspicious keywords for hard-coded secrets
suspicious_keywords = {"password", "passphrase", "secret", "token", "key", "credentials", "admin_password", "root_password", "db_password", "default_password", "initial_password", "connection_string", "login_password", "auth_secret", "api_key", "secret_key", "access_token", "admin_pass", "pwd", "dsn", "uri", "truststore_password", "keystore_password"}

# Helper function to check if string contains hard-coded secret pattern
is_hardcoded_secret_string(str) {
    # Check for common password patterns in strings
    regex.match(`(?i)(password|pass|pwd|secret|token|key|auth|credential)\s*=\s*[^$]`, str)
} else {
    # Check for Base64-like patterns that might be encoded secrets
    regex.match(`^[A-Za-z0-9+/]*={0,2}$`, str)
    count(str) > 8  # Longer than typical random strings
} else {
    # Check for simple hard-coded values
    regex.match(`(?i)^(password|pass|pwd|secret|123456|admin|root)$`, str)
}

# Helper function to check if value is a secure pattern
is_secure_pattern(value) {
    value.ir_type == "VariableReference"
} else {
    value.ir_type == "FunctionCall"
    regex.match(`(?i)(secrets_manager|vault_secret|parameter_store|secret_ref|encrypted|kms_key_id|vault\.parse|var\.)`, value.name)
} else {
    value.ir_type == "MethodCall"
    regex.match(`(?i)(secrets_manager|vault_secret|parameter_store|secret_ref|encrypted|kms_key_id|vault\.parse|var\.)`, value.method)
} else {
    value.ir_type == "String"
    regex.match(`^\$\{`, value.value)  # Variable interpolation
} else {
    value.ir_type == "String"
    regex.match(`^var\.`, value.value)  # Variable reference in string
}

# Rule 1: Check direct variables and attributes with suspicious names
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all variables
    variable := glitch_lib.all_variables(parent)[_]
    suspicious_keywords[variable.name]
    variable.value.ir_type == "String"
    variable.value.value != ""
    not is_secure_pattern(variable.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": variable,
        "path": parent.path,
        "description": "Hard-coded secret in variable. (CWE-259)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all attributes
    attr := glitch_lib.all_attributes(parent)[_]
    suspicious_keywords[attr.name]
    attr.value.ir_type == "String"
    attr.value.value != ""
    not is_secure_pattern(attr.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded secret in attribute. (CWE-259)"
    }
}

# Rule 2: Check Hash values for nested secrets
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    some i
    item := node.value[i]
    item.key.ir_type == "String"
    suspicious_keywords[item.key.value]
    item.value.ir_type == "String"
    item.value.value != ""
    not is_secure_pattern(item.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": item.value,
        "path": parent.path,
        "description": "Hard-coded secret in hash. (CWE-259)"
    }
}

# Rule 3: Check Array values for secrets (like environment variables)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Array"
    
    # Check each element in the array
    some i
    element := node.value[i]
    element.ir_type == "String"
    element.value != ""
    
    # Check if string contains password assignment pattern
    is_hardcoded_secret_string(element.value)
    not is_secure_pattern(element)
    
    result := {
        "type": "sec_hard_pass",
        "element": element,
        "path": parent.path,
        "description": "Hard-coded secret in array element. (CWE-259)"
    }
}

# Rule 4: Check for strings containing password patterns in any context
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "String"
    node.value != ""
    
    # Check if string contains hard-coded secret pattern
    is_hardcoded_secret_string(node.value)
    not is_secure_pattern(node)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "String containing hard-coded secret pattern. (CWE-259)"
    }
}