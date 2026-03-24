package glitch

import data.glitch_lib

# Define patterns for network-related keys and unrestricted addresses
network_key_pattern := "(?i).*(ip|addr|address|bind|host|socket|endpoint|binding).*"
unrestricted_address_pattern := "(?i)^(0\\.0\\.0\\.0|\\*|::|all|public|0\\.0\\.0\\.)$"

# Helper to check if a key suggests network binding
is_network_key(key) {
    key.ir_type == "String"
    regex.match(network_key_pattern, key.value)
} else {
    key.ir_type == "VariableReference"
    regex.match(network_key_pattern, key.value)
}

# Helper to check if a value is an unrestricted address
is_unrestricted_address(value) {
    value.ir_type == "String"
    regex.match(unrestricted_address_pattern, value.value)
} else {
    value.ir_type == "Integer"
    value.value == 0
}

# Rule 1: Check Hash nodes for unrestricted addresses in network keys
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk through all nodes to find Hash nodes
    walk(parent, [path, n])
    n.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    pair := n.value[_]
    key := pair.key
    value := pair.value
    
    # Check if the key suggests network binding and value is unrestricted
    is_network_key(key)
    is_unrestricted_address(value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": n,
        "path": parent.path,
        "description": "Insecure network binding detected - Binding to unrestricted address may allow unauthorized access. (CWE-284)"
    }
}

# Rule 2: Check Attribute nodes for unrestricted addresses in network keys
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check if attribute name suggests network binding and value is unrestricted
    is_network_key({"ir_type": "String", "value": attr.name})
    is_unrestricted_address(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Insecure network binding detected - Binding to unrestricted address may allow unauthorized access. (CWE-284)"
    }
}

# Rule 3: Check Variable nodes for unrestricted addresses in network keys
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if variable name suggests network binding and value is unrestricted
    is_network_key({"ir_type": "String", "value": var.name})
    is_unrestricted_address(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Insecure network binding detected - Binding to unrestricted address may allow unauthorized access. (CWE-284)"
    }
}

# Rule 4: Check for insecure network binding in FunctionCall arguments
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk through all nodes to find FunctionCall nodes
    walk(parent, [path, n])
    n.ir_type == "FunctionCall"
    
    # Check if function name suggests network binding
    regex.match("(?i).*(bind|listen|connect|socket).*", n.name)
    
    # Check arguments for unrestricted addresses
    arg := n.args[_]
    is_unrestricted_address(arg)
    
    result := {
        "type": "sec_invalid_bind",
        "element": n,
        "path": parent.path,
        "description": "Insecure network binding detected in function call - Binding to unrestricted address may allow unauthorized access. (CWE-284)"
    }
}