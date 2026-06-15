package glitch

import data.glitch_lib

sensitive_fields := {"password", "pass", "pwd", "secret", "token", "key", "apikey", "accesskey", "secretkey", "privatekey", "credential", "auth"}
default_credentials := {"admin", "password123", "changeme", "default", "test", "demo"}
base64_pattern := "^[A-Za-z0-9+/]{20,}={0,2}$"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in atomic units
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if attribute name matches sensitive field patterns
    sensitive_fields[attr.name]
    
    # Check if value is a hardcoded string (not a variable reference)
    attr.value.ir_type == "String"
    value := attr.value.value
    
    # Check for base64 patterns or default credentials
    (regex.match(base64_pattern, value) or default_credentials[value])
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded credentials in IaC configuration. (CWE-798)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables in unit blocks
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Check if variable name matches sensitive field patterns
    sensitive_fields[var.name]
    
    # Check if value is a hardcoded string (not a variable reference)
    var.value.ir_type == "String"
    value := var.value.value
    
    # Check for base64 patterns or default credentials
    (regex.match(base64_pattern, value) or default_credentials[value])
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded credentials in IaC variables. (CWE-798)"
    }
}