package glitch

import data.glitch_lib

# Helper function to check if a key name matches binding patterns
matches_binding_pattern(key_name) = true {
    # Convert to lowercase for case-insensitive matching
    lower_key := lower(key_name)
    # Check for binding-related keywords
    regex.match(".*(bind|listen|ip|host|server|public|container_network|service_bind|public_ip).*", lower_key)
} else = false

# Helper function to extract string value from different key types
get_key_string(key) = str {
    key.ir_type == "String"
    str := key.value
} else = str {
    key.ir_type == "VariableReference"
    str := key.value
} else = str {
    # For other types, try to get string representation
    str := ""
}

# Rule to detect unrestricted IP binding in Hash key-value pairs (like in Chef variables)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk through all nodes in the parent to find Hash nodes
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    pair := node.value[_]
    key_str := get_key_string(pair.key)
    
    # Check if the key matches binding patterns and value is "0.0.0.0"
    matches_binding_pattern(key_str)
    pair.value.ir_type == "String"
    pair.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": pair.value,
        "path": parent.path,
        "description": "Binding to unrestricted IP address 0.0.0.0 - Service binds to all network interfaces, potentially exposing to unauthorized access. (CWE-1327)"
    }
}

# Rule to detect unrestricted IP binding in Variables (common in Ansible, Chef, Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all variables in the parent
    vars := glitch_lib.all_variables(parent)
    var_node := vars[_]
    
    # Check if variable name matches binding patterns and value is "0.0.0.0"
    matches_binding_pattern(var_node.name)
    var_node.value.ir_type == "String"
    var_node.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": var_node,
        "path": parent.path,
        "description": "Binding to unrestricted IP address 0.0.0.0 - Service binds to all network interfaces, potentially exposing to unauthorized access. (CWE-1327)"
    }
}

# Rule to detect unrestricted IP binding in Attributes (common in Ansible, Chef, Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all attributes in the parent
    attrs := glitch_lib.all_attributes(parent)
    attr_node := attrs[_]
    
    # Check if attribute name matches binding patterns and value is "0.0.0.0"
    matches_binding_pattern(attr_node.name)
    attr_node.value.ir_type == "String"
    attr_node.value.value == "0.0.0.0"
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr_node,
        "path": parent.path,
        "description": "Binding to unrestricted IP address 0.0.0.0 - Service binds to all network interfaces, potentially exposing to unauthorized access. (CWE-1327)"
    }
}