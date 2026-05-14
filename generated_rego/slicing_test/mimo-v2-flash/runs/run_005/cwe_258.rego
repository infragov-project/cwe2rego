package glitch

import data.glitch_lib

# Define credential-related keywords
credential_keywords := {"password", "pass", "pwd", "secret", "token", "api_key", "credential", "auth", "key", "secret_key", "access_key", "api_token", "proxy_password", "replication_password", "sslclientkey"}

# Helper to check if a name is credential-related
is_credential_name(name) {
    lower_name := lower(name)
    some kw
    credential_keywords[kw]
    contains(lower_name, kw)
}

# Rule 1: Detect empty string assignment in variables (Ansible)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get variables from the unit block
    some var_node in parent.variables
    
    # Check if name indicates credential
    is_credential_name(var_node.name)
    
    # Check for empty string value
    var_node.value.ir_type == "String"
    var_node.value.value == ""
    
    result := {
        "type": "sec_empty_pass",
        "element": var_node,
        "path": parent.path,
        "description": "Empty password in configuration file - Avoid setting credentials to empty values. (CWE-258)",
    }
}

# Rule 2: Detect null assignment in variables (Chef)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get variables from the unit block
    some var_node in parent.variables
    
    # Check if name indicates credential
    is_credential_name(var_node.name)
    
    # Check for null value
    var_node.value.ir_type == "Null"
    
    result := {
        "type": "sec_empty_pass",
        "element": var_node,
        "path": parent.path,
        "description": "Empty password in configuration file - Avoid setting credentials to empty values. (CWE-258)",
    }
}

# Rule 3: Detect undef assignment in attributes (Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check nested unit blocks for attributes (Puppet class parameters)
    some ub in parent.unit_blocks
    some attr in ub.attributes
    
    # Check if name indicates credential
    is_credential_name(attr.name)
    
    # Check for Undef value
    attr.value.ir_type == "Undef"
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Avoid setting credentials to empty values. (CWE-258)",
    }
}

# Rule 4: Detect undef assignment in variables (Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check nested unit blocks for variables (Puppet local variables)
    some ub in parent.unit_blocks
    some var_node in ub.variables
    
    # Check if name indicates credential
    is_credential_name(var_node.name)
    
    # Check for Undef value
    var_node.value.ir_type == "Undef"
    
    result := {
        "type": "sec_empty_pass",
        "element": var_node,
        "path": parent.path,
        "description": "Empty password in configuration file - Avoid setting credentials to empty values. (CWE-258)",
    }
}