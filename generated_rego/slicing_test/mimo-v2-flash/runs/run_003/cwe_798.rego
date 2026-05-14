package glitch

import data.glitch_lib

# Set of keywords that indicate potential hard-coded credentials or secrets
sensitive_keywords := {
    "password", "secret", "token", "key", "credential", "auth",
    "passphrase", "pwd", "pass", "access_key", "secret_key",
    "private_key", "api_key", "certificate", "ssh_key", "truststore",
    "user", "username", "client_auth", "require_client_auth"
}

# Helper function to check if a string contains a sensitive keyword
contains_sensitive_keyword(str) {
    lower_str := lower(str)
    kw := sensitive_keywords[_]
    contains(lower_str, kw)
}

# Check if a value is a hardcoded secret (not a variable reference)
is_hardcoded_secret(value) {
    value.ir_type == "String"
    count(value.value) > 0
    not glitch_lib.has_variable_reference(value)
}

# Rule for Variables (e.g., Chef attributes, Puppet parameters)
Glitch_Analysis[result] {
    # Gather all variables from the input
    vars := glitch_lib.all_variables(input)
    var := vars[_]
    
    # Check if variable name contains a sensitive keyword
    contains_sensitive_keyword(var.name)
    
    # Check if value is a hardcoded string
    is_hardcoded_secret(var.value)
    
    # Get parent path
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid embedding sensitive data directly in code. (CWE-798)"
    }
}

# Rule for Attributes (e.g., resource attributes in Ansible, Chef resources)
Glitch_Analysis[result] {
    # Gather all attributes from the input
    attrs := glitch_lib.all_attributes(input)
    attr := attrs[_]
    
    # Check if attribute name contains a sensitive keyword
    contains_sensitive_keyword(attr.name)
    
    # Check if value is a hardcoded string
    is_hardcoded_secret(attr.value)
    
    # Get parent path
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid embedding sensitive data directly in code. (CWE-798)"
    }
}

# Rule for Hash keys (e.g., nested credentials in YAML or JSON-like structures)
Glitch_Analysis[result] {
    # Walk through all hash nodes in the input
    walk(input, [path, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    pair := node.value[_]
    key := pair.key
    value := pair.value
    
    # Check if the key contains a sensitive keyword
    key.ir_type == "String"
    contains_sensitive_keyword(key.value)
    
    # Check if the value is a hardcoded secret
    is_hardcoded_secret(value)
    
    # Get parent path
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    result := {
        "type": "sec_hard_secr",
        "element": key,
        "path": parent.path,
        "description": "Use of Hard-coded Credentials - Avoid embedding sensitive data directly in code. (CWE-798)"
    }
}