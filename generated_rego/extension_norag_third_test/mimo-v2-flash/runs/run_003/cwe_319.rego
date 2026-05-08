package glitch

import data.glitch_lib

# Insecure attribute names that indicate cleartext transmission risks
insecure_attr_names := {
    "protocol", "port", "disable_tls", "ssl", "use_ssl", "enable_https", 
    "encryption", "secure_connection", "tls_version", "ssl_policy", 
    "enforce_https", "redirect_http_to_https", "enable_https_traffic_only", 
    "force_ssl", "start_tls", "ssl_skip_verify", "validate_certs"
}

# Values that indicate insecure configurations
insecure_string_values := {
    "http", "ftp", "telnet", "smtp", "plaintext", "disabled", "false", 
    "no", "none", "disable", "80"
}

# Pattern for insecure URLs
insecure_url_pattern := "^(http|ftp|telnet)://"

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables for insecure settings in hash values
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Walk through the variable value to find hash nodes
    walk(var.value, [path, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash using old-style iteration
    some pair
    pair := node.value[_]
    key := pair.key
    value := pair.value
    
    # Check if the key is an insecure attribute name
    key.ir_type == "String"
    insecure_attr_names[key.value]
    
    # Check if the value is insecure
    value.ir_type == "String"
    insecure_string_values[value.value]
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure configuration detected in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables for boolean false values in insecure attributes
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Walk through the variable value to find hash nodes
    walk(var.value, [path, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash using old-style iteration
    some pair
    pair := node.value[_]
    key := pair.key
    value := pair.value
    
    # Check if the key is an insecure attribute name
    key.ir_type == "String"
    insecure_attr_names[key.value]
    
    # Check if the value is boolean false
    value.ir_type == "Boolean"
    value.value == false
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Security feature disabled in variable (boolean). (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in atomic units for insecure settings
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check attribute name and value
    insecure_attr_names[attr.name]
    attr.value.ir_type == "String"
    insecure_string_values[attr.value.value]
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure attribute configuration. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables for insecure URLs
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Use traverse to check for insecure URL patterns
    glitch_lib.traverse(var.value, insecure_url_pattern)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure URL detected in variable. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes for insecure URLs
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Use traverse to check for insecure URL patterns in attribute value
    glitch_lib.traverse(attr.value, insecure_url_pattern)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Insecure URL detected in attribute. (CWE-319)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for boolean false values in insecure attributes
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for insecure attribute names with boolean false values
    insecure_attr_names[attr.name]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Cleartext Transmission of Sensitive Information - Security feature disabled (boolean). (CWE-319)"
    }
}