package glitch

import data.glitch_lib

# Keywords indicating sensitive information (case-insensitive matching)
sensitive_names := {"password", "secret", "api_key", "token", "credential", "auth", "key", "passphrase", "private_key", "secret_key", "access_key", "client_secret", "db_password", "admin_password", "root_password", "sha512_password"}

# Patterns indicating secure secret management (which should NOT trigger a finding)
secret_reference_patterns := {"\\$\\{", "\\{\\{.*\\}\\}", "lookup\\(", "env\\(", "ssm_parameter", "secretsmanager", "key_vault", "secret_ref"}

# Helper function to check if a string contains any of the given substrings
contains_any(str, substrings) {
    substring := substrings[_]
    contains(lower(str), lower(substring))
}

# Helper function to check if a value is a secure reference
is_secret_reference(val) {
    pattern := secret_reference_patterns[_]
    regex.match(pattern, val)
}

# Recursive function to find all sensitive attributes within a node (including nested Hashes and Arrays)
find_sensitive_attributes(node) = attrs {
    # Walk the entire node structure to find all Attributes or Variables
    walk(node, [path, n])
    
    # Check if the node is an Attribute (Ansible/YAML) or Variable (Chef/Ruby)
    (n.ir_type == "Attribute" or n.ir_type == "Variable")
    
    # Get the name and value of the node
    name := n.name
    value := n.value
    
    # Check if the name contains a sensitive keyword
    contains_any(name, sensitive_names)
    
    # Check if the value is a literal string (not a variable reference or function call)
    value.ir_type == "String"
    
    # Check if the value does NOT contain a secure reference pattern
    not is_secret_reference(value.value)
    
    # Collect the matching node
    attrs := {n}
}

# Main rule to detect hardcoded credentials
Glitch_Analysis[result] {
    # Identify the context (e.g., a file/vars block)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Find sensitive attributes within the context
    sensitive_attributes := find_sensitive_attributes(parent)
    attr := sensitive_attributes[_]
    
    # Construct the result
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - The product contains hard-coded credentials. (CWE-798)"
    }
}