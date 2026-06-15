package glitch

import data.glitch_lib

# Define the pattern for unrestricted IP
unrestricted_ip_pattern := "^(0\\.0\\.0\\.0|::|::0|0\\.0\\.0\\.0/0)$"

# Define the keywords for binding and firewall
binding_keywords := {"bind", "listen", "address", "ip", "host", "interface", "server_address", "listen_address", "bind_address", "bind_addr", "bind_ip", "container_ip", "host_ip"}
firewall_keywords := {"cidr", "source", "ingress", "from", "allowed", "network_interfaces"}

# Helper function to check if a node has unrestricted IP
check_unrestricted_ip(node) {
    glitch_lib.traverse(node, unrestricted_ip_pattern)
}

# Rule for variables with simple string value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Check if the variable's value is unrestricted IP
    check_unrestricted_ip(var.value)
    
    # Check the variable name for binding or firewall keywords
    (contains(var.name, binding_keywords[_]) or contains(var.name, firewall_keywords[_]))
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - The service is bound to 0.0.0.0, which may allow unintended access from any IP address. (CWE-1327)"
    }
}

# Rule for variables with hash value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    # Check if the variable's value is a hash and contains an unrestricted IP in a key that matches keywords
    var.value.ir_type == "Hash"
    some pair in var.value.value
    key := pair.key
    value := pair.value
    
    # Check if the key matches binding or firewall keywords
    (key.ir_type == "String" and (contains(key.value, binding_keywords[_]) or contains(key.value, firewall_keywords[_]))) or
    (key.ir_type == "VariableReference" and (contains(key.value, binding_keywords[_]) or contains(key.value, firewall_keywords[_])))
    
    # Check if the value is unrestricted IP
    check_unrestricted_ip(value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - The service is bound to 0.0.0.0, which may allow unintended access from any IP address. (CWE-1327)"
    }
}

# Rule for attributes with simple string value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if the attribute's value is unrestricted IP
    check_unrestricted_ip(attr.value)
    
    # Check the attribute name for binding or firewall keywords
    (contains(attr.name, binding_keywords[_]) or contains(attr.name, firewall_keywords[_]))
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - The service is bound to 0.0.0.0, which may allow unintended access from any IP address. (CWE-1327)"
    }
}

# Rule for attributes with hash value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if the attribute's value is a hash and contains an unrestricted IP in a key that matches keywords
    attr.value.ir_type == "Hash"
    some pair in attr.value.value
    key := pair.key
    value := pair.value
    
    # Check if the key matches binding or firewall keywords
    (key.ir_type == "String" and (contains(key.value, binding_keywords[_]) or contains(key.value, firewall_keywords[_]))) or
    (key.ir_type == "VariableReference" and (contains(key.value, binding_keywords[_]) or contains(key.value, firewall_keywords[_])))
    
    # Check if the value is unrestricted IP
    check_unrestricted_ip(value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an unrestricted IP address - The service is bound to 0.0.0.0, which may allow unintended access from any IP address. (CWE-1327)"
    }
}