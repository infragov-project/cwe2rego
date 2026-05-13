package glitch

import data.glitch_lib

# Sensitive keywords indicating potential credentials
sensitive_keywords := {"password", "pwd", "secret", "token", "key", "api_key", "credential", "auth", "passphrase", "secret_key", "access_key", "private_key", "ssh_key"}

# Check if a string value contains hard-coded credential patterns
is_hardcoded_credential(value) {
    value.ir_type == "String"
    # Check for base64 encoded strings (common pattern for obfuscated secrets)
    regex.match("^[A-Za-z0-9+/]{20,}={0,2}$", value.value)
} else {
    value.ir_type == "String"
    # Check for common weak passwords or default credentials
    regex.match("(?i)^(admin|root|password|123456|letmein|qwerty|test)$", value.value)
} else {
    value.ir_type == "String"
    # Check for non-empty, non-reference strings that might be credentials
    count(value.value) > 0
    not startswith(value.value, "${")
    not startswith(value.value, "{{")
}

# Check if a name indicates a sensitive field
is_sensitive_name(name) {
    sensitive_keywords[name]
} else {
    some keyword in sensitive_keywords
    regex.match(sprintf("(?i).*%s.*", [keyword]), name)
}

# Recursively check a node for hard-coded credentials in nested structures
find_hardcoded_credential(node) {
    node.ir_type == "Hash"
    some key, val in node.value
    is_sensitive_name(key.value)
    is_hardcoded_credential(val)
} else {
    node.ir_type == "Hash"
    some key, val in node.value
    find_hardcoded_credential(val)
} else {
    node.ir_type == "Array"
    some element in node.value
    find_hardcoded_credential(element)
}

# Check variables in unit blocks for hard-coded credentials
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    
    # Check if variable name indicates sensitivity
    is_sensitive_name(v.name)
    
    # Check if value is hardcoded (not a variable reference)
    v.value.ir_type != "VariableReference"
    find_hardcoded_credential(v.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": v,
        "path": parent.path,
        "description": "Hard-coded credential in variable - Variables should not have sensitive default values. (CWE-798)"
    }
}

# Check attributes in atomic units for hard-coded credentials
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if attribute name indicates sensitivity
    is_sensitive_name(attr.name)
    
    # Check if value is hardcoded (not a variable reference)
    attr.value.ir_type != "VariableReference"
    find_hardcoded_credential(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hard-coded credential in resource configuration - Credentials should be stored in secure secret management services. (CWE-798)"
    }
}

# Check for hardcoded credentials in connection strings or URIs
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for connection string, datasource, endpoint, or uri attributes
    regex.match("(?i).*(connection_string|datasource|endpoint|uri).*", attr.name)
    
    # Check if value contains embedded credentials (e.g., username:password@host)
    attr.value.ir_type == "String"
    regex.match(".*[:@].*[:@].*", attr.value.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Embedded credentials in connection string - Use secure secret management instead. (CWE-798)"
    }
}