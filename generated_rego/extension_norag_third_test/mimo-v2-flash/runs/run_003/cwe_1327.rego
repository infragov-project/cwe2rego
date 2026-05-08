package glitch

import data.glitch_lib

# Define patterns for binding address keys (case-insensitive)
binding_key_patterns := {"bind", "listen", "address", "ip", "endpoint", "interface", "host", "server", "network"}

# Check if a string value represents an unrestricted IP
is_unrestricted_ip(v) {
    v.ir_type == "String"
    regex.match("^(0\\.0\\.0\\.0|::)$", v.value)
} else {
    v.ir_type == "VariableReference"
    regex.match("^(0\\.0\\.0\\.0|::)$", v.value)
}

# Check if a key name matches binding patterns
matches_binding_key(key_name) {
    # Convert key to lowercase for case-insensitive matching
    lower_key := lower(key_name)
    pattern := binding_key_patterns[_]
    contains(lower_key, pattern)
}

# Check if a node's name matches binding patterns
matches_binding_node_name(node) {
    node.name != ""
    matches_binding_key(node.name)
}

# Check if a hash contains unrestricted IP in a binding key
check_hash_for_binding(hash_val) {
    hash_val.ir_type == "Hash"
    some pair in hash_val.value
    key_str := get_key_string(pair.key)
    matches_binding_key(key_str)
    is_unrestricted_ip(pair.value)
}

# Helper to convert key to string (handles VariableReference and String)
get_key_string(key) = str {
    key.ir_type == "String"
    str := key.value
} else {
    key.ir_type == "VariableReference"
    str := key.value
}

# Main detection rule for variables and attributes with direct unrestricted IP
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    matches_binding_node_name(variable)
    is_unrestricted_ip(variable.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": variable,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0 or ::) - This may expose the service to unintended remote access. (CWE-1327)"
    }
}

# Main detection rule for attributes with direct unrestricted IP
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes
    attributes := glitch_lib.all_attributes(parent)
    attribute := attributes[_]
    matches_binding_node_name(attribute)
    is_unrestricted_ip(attribute.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attribute,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0 or ::) - This may expose the service to unintended remote access. (CWE-1327)"
    }
}

# Detection for variables with hash values containing unrestricted IP
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    variable.value.ir_type == "Hash"
    check_hash_for_binding(variable.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": variable,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0 or ::) in configuration hash - This may expose the service to unintended remote access. (CWE-1327)"
    }
}

# Detection for attributes with hash values containing unrestricted IP
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attributes := glitch_lib.all_attributes(parent)
    attribute := attributes[_]
    attribute.value.ir_type == "Hash"
    check_hash_for_binding(attribute.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attribute,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0 or ::) in configuration hash - This may expose the service to unintended remote access. (CWE-1327)"
    }
}

# Detection for deeply nested hashes (recursive approach)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check all variables and attributes for nested hash structures
    all_nodes := glitch_lib.all_variables(parent) | glitch_lib.all_attributes(parent)
    node := all_nodes[_]
    
    # Use walk to find nested hashes
    walk(node, [path, n])
    n.ir_type == "Hash"
    check_hash_for_binding(n)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0 or ::) in nested configuration - This may expose the service to unintended remote access. (CWE-1327)"
    }
}