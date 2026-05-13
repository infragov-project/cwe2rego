package glitch

import data.glitch_lib

# Define keywords that indicate a bind address configuration
bind_keywords := {"bind", "ip", "address", "addr", "net", "port", "listen"}

# Helper function to check if a string value indicates all interfaces
is_all_interfaces(value) {
    value.ir_type == "String"
    regex.match("^(0\\.0\\.0\\.0|::/0)$", value.value)
}

# Helper function to check if a key name indicates bind configuration
is_bind_key(key) {
    key.ir_type == "String"
    contains(key.value, bind_keywords[_])
} else {
    key.ir_type == "VariableReference"
    contains(key.value, bind_keywords[_])
}

# Rule to detect bind to all interfaces in Variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    
    # Check if variable name indicates bind configuration
    contains(variable.name, bind_keywords[_])
    
    # Check if value is all interfaces
    is_all_interfaces(variable.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": variable,
        "path": parent.path,
        "description": "Resource binds to all network interfaces (0.0.0.0) - Restrict access to specific IPs or localhost. (CWE-284)"
    }
}

# Rule to detect bind to all interfaces in Attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if attribute name indicates bind configuration
    contains(attr.name, bind_keywords[_])
    
    # Check if value is all interfaces
    is_all_interfaces(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Resource binds to all network interfaces (0.0.0.0) - Restrict access to specific IPs or localhost. (CWE-284)"
    }
}

# Rule to detect bind to all interfaces in Hash structures (nested in variables)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    variable := variables[_]
    
    # Check if variable value is a Hash
    variable.value.ir_type == "Hash"
    
    # Traverse the hash to find bind configuration
    walk(variable.value, [path, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    pair := node.value[_]
    is_bind_key(pair.key)
    is_all_interfaces(pair.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": pair.value,
        "path": parent.path,
        "description": "Resource binds to all network interfaces (0.0.0.0) in configuration hash - Restrict access to specific IPs or localhost. (CWE-284)"
    }
}

# Rule to detect bind to all interfaces in Hash structures (nested in attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if attribute value is a Hash
    attr.value.ir_type == "Hash"
    
    # Traverse the hash to find bind configuration
    walk(attr.value, [path, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    pair := node.value[_]
    is_bind_key(pair.key)
    is_all_interfaces(pair.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": pair.value,
        "path": parent.path,
        "description": "Resource binds to all network interfaces (0.0.0.0) in configuration hash - Restrict access to specific IPs or localhost. (CWE-284)"
    }
}