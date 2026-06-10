package glitch

import data.glitch_lib

# Helper to check for insecure protocols in string values
insecure_protocol(value) {
    value.ir_type == "String"
    regex.match("(?i)^(http|ftp|smtp|telnet)$", value.value)
}

# Helper to check for insecure URLs in string values
insecure_url(value) {
    value.ir_type == "String"
    regex.match("(?i)^http://", value.value)
}

# Helper to check for disabled SSL/HTTPS in boolean or string values
disabled_ssl(value) {
    value.ir_type == "Boolean"
    value.value == false
} else {
    value.ir_type == "String"
    regex.match("(?i)^(no|false|disabled|none)$", value.value)
}

# Rule 1: Check AtomicUnit attributes for insecure protocols
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for insecure protocol in attribute value
    insecure_protocol(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol in configuration. (CWE-319)"
    }
}

# Rule 2: Check AtomicUnit attributes for insecure URLs
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for insecure URL in attribute value
    insecure_url(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure URL in configuration. (CWE-319)"
    }
}

# Rule 3: Check AtomicUnit attributes for disabled SSL/HTTPS
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for SSL/HTTPS disabled
    disabled_ssl(attr.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - SSL/HTTPS disabled in configuration. (CWE-319)"
    }
}

# Rule 4: Check variables in vars unit blocks for insecure URLs
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    parent.type == "vars"
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Check variable value for insecure URLs using traverse
    glitch_lib.traverse(var.value, "(?i)^http://")
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure URL in variable. (CWE-319)"
    }
}

# Rule 5: Check Hash entries in variables for insecure protocol settings
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    parent.type == "vars"
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Check if variable value is a Hash
    var.value.ir_type == "Hash"
    
    # Iterate through Hash entries
    entry := var.value.value[_]
    entry.key.ir_type == "String"
    entry.value.ir_type == "String"
    
    # Check for protocol setting to insecure value
    entry.key.value == "protocol"
    insecure_protocol(entry.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure protocol in variable hash. (CWE-319)"
    }
}

# Rule 6: Check complex expressions (like Sum) for insecure URLs in AtomicUnit attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Use traverse to check for insecure URLs in complex expressions
    glitch_lib.traverse(attr.value, "(?i)^http://")
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext transmission of sensitive information - Insecure URL in complex expression. (CWE-319)"
    }
}