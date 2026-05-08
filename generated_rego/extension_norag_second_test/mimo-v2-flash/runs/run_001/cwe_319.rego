package glitch

import data.glitch_lib

# Detect insecure protocol in String values (e.g., "http://")
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Variables directly (e.g., Ansible Vars, Chef Attributes)
    var := parent.variables[_]
    glitch_lib.traverse(var.value, "http://")
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted HTTP URL. (CWE-319)"
    }
}

# Detect insecure protocol in Atomic Units (e.g., Resources/Tasks)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    glitch_lib.traverse(attr.value, "http://")
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Unencrypted HTTP URL. (CWE-319)"
    }
}

# Detect disabled security flags (e.g., ssl: false, validate_certs: no)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Variables directly
    var := parent.variables[_]
    
    # Check if variable name implies security settings
    regex.match("ssl|tls|https|encrypt|validate|secure", var.name)
    
    # Check if value disables security
    check_disabled_security(var.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Security validation disabled. (CWE-319)"
    }
}

# Detect disabled security flags in Atomic Units
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if attribute name implies security settings
    regex.match("ssl|tls|https|encrypt|validate|secure", attr.name)
    
    # Check if value disables security
    check_disabled_security(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Security validation disabled. (CWE-319)"
    }
}

# Helper to check if a value disables security
check_disabled_security(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    re_match("^(no|false|disabled|0)$", value.value)
}