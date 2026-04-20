package glitch

import data.glitch_lib

# Detect insecure protocol usage (HTTP URLs)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Find String nodes containing http:// (case insensitive)
    walk(parent, [path, node])
    node.ir_type == "String"
    regex.match("(?i)^http://", node.value)
    
    # Ensure it's not a GPG key or similar false positive
    # Check if the string is part of an attribute value that's likely a URL/connection string
    attrs := glitch_lib.all_attributes(parent)
    some attr
    attr := attrs[_]
    attr.value == node
    
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Insecure HTTP protocol usage in transmission endpoint (CWE-319)"
    }
}

# Detect insecure protocol in configuration hashes (e.g., protocol: http)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Find Hash nodes with protocol attribute set to http
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    some i
    key_value := node.value[i]
    key := key_value.key
    value := key_value.value
    key.ir_type == "String"
    key.value == "protocol"
    value.ir_type == "String"
    value.value == "http"
    
    result := {
        "type": "sec_https",
        "element": value,
        "path": parent.path,
        "description": "Insecure protocol in configuration hash (CWE-319)"
    }
}

# Detect plaintext secrets in attributes (with stricter pattern matching)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    some attr
    attr := attrs[_]
    
    # Only flag attributes that are clearly secrets (avoid false positives on "key" alone)
    regex.match("(?i)(password|secret|api_key|token|private_key|secret_key|credential)", attr.name)
    attr.value.ir_type == "String"
    attr.value.value != ""
    
    # Exclude common non-secret keys (like GPG keys)
    not regex.match("(?i)^[0-9A-F]{40}$", attr.value.value)  # Exclude 40-character hex strings (GPG keys)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Secret in plaintext attribute (CWE-319)"
    }
}

# Detect insecure database connection strings
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "String"
    regex.match("(?i)^(mysql://|postgres://|mongodb://|http://)", node.value)
    
    result := {
        "type": "sec_https",
        "element": node,
        "path": parent.path,
        "description": "Cleartext database connection string (CWE-319)"
    }
}

# Detect insecure ports
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    some attr
    attr := attrs[_]
    attr.name == "port"
    attr.value.ir_type == "Integer"
    insecure_ports := {80, 21, 23}
    attr.value.value == insecure_ports[_]
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "Insecure port configuration (CWE-319)"
    }
}

# Detect HTTP URLs in variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    some var
    var := variables[_]
    var.value.ir_type == "String"
    regex.match("(?i)^http://", var.value.value)
    
    result := {
        "type": "sec_https",
        "element": var,
        "path": parent.path,
        "description": "Insecure HTTP URL in variable (CWE-319)"
    }
}

# Detect disabled SSL/TLS validation
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    some attr
    attr := attrs[_]
    
    attr.name == "validate_certs"
    attr.value.ir_type == "String"
    regex.match("(?i)^(no|false|disabled)$", attr.value.value)
    
    result := {
        "type": "sec_https",
        "element": attr,
        "path": parent.path,
        "description": "SSL/TLS certificate validation disabled (CWE-319)"
    }
}