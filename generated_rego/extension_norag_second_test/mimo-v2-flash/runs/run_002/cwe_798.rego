package glitch

import data.glitch_lib

# Set of common credential-related field names
credential_fields := {
    "password", "secret", "token", "key", "auth", "credential", "apikey",
    "access_key", "secret_key", "private_key", "master_user_password",
    "admin_password", "db_password", "encryption_key", "jwt_secret",
    "ssl_key", "connection_string", "api_key", "sha512_password"
}

# Helper function to check if value is a hardcoded credential
is_hardcoded_credential(value) {
    value.ir_type == "String"
    value.value != ""
    # Exclude variable references, environment variables, and common templating
    not regex.match("^\\$\\{.*\\}$", value.value)
    not regex.match("^\\$[A-Z_]+$", value.value)
    not regex.match("^var\\..*", value.value)
    not regex.match("^\\[.*\\]$", value.value)
    not regex.match("^\\{\\{.*\\}\\}$", value.value)
    not regex.match("^env\\..*", value.value)
}

# Helper to check if string contains substring (case-insensitive)
contains(str, substr) {
    regex.match(sprintf("(?i).*%s.*", [substr]), str)
}

# Rule 1: Direct credential detection in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Check variable name for credential patterns
    lower_name := lower(var.name)
    contains_credential := contains(lower_name, "password") or 
                          contains(lower_name, "secret") or 
                          contains(lower_name, "token") or 
                          contains(lower_name, "key") or
                          contains(lower_name, "auth") or
                          contains(lower_name, "credential")
    contains_credential
    
    # Check if value is hardcoded
    is_hardcoded_credential(var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid embedding static, unencrypted sensitive values directly in code. (CWE-798)"
    }
}

# Rule 2: Direct credential detection in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check attribute name against credential fields
    lower_name := lower(attr.name)
    credential_fields[_] == lower_name
    
    # Check if value is hardcoded
    is_hardcoded_credential(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials - Avoid embedding static, unencrypted sensitive values directly in code. (CWE-798)"
    }
}

# Rule 3: Nested credential detection in Hash structures
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Search all possible containers
    containers := array.concat(
        glitch_lib.all_variables(parent),
        glitch_lib.all_attributes(parent)
    )
    container := containers[_]
    
    # Only process Hash values
    container.value.ir_type == "Hash"
    
    # Walk through the Hash to find credential attributes
    walk(container.value, [path, n])
    n.ir_type == "Attribute"
    lower_name := lower(n.name)
    credential_fields[_] == lower_name
    is_hardcoded_credential(n.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": n,
        "path": parent.path,
        "description": "Use of hard-coded credentials in nested configuration - Avoid embedding static secrets in nested structures. (CWE-798)"
    }
}

# Rule 4: Nested credential detection in Array structures
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Search all possible containers
    containers := array.concat(
        glitch_lib.all_variables(parent),
        glitch_lib.all_attributes(parent)
    )
    container := containers[_]
    
    # Only process Array values
    container.value.ir_type == "Array"
    
    # Walk through the Array to find credential attributes
    walk(container.value, [path, n])
    n.ir_type == "Attribute"
    lower_name := lower(n.name)
    credential_fields[_] == lower_name
    is_hardcoded_credential(n.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": n,
        "path": parent.path,
        "description": "Use of hard-coded credentials in nested configuration - Avoid embedding static secrets in nested structures. (CWE-798)"
    }
}