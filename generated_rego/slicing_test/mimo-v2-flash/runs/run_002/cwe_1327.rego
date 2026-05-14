package glitch

import data.glitch_lib

# Helper to check if a key represents a binding attribute
is_binding_attribute(key_node) {
    key_node.ir_type == "String"
    binding_attrs := {"ip", "bind-address", "bind_address", "listen_address", "listenaddr", "bindaddr", "host", "ip_address", "server_address", "mongodb_net_bindip", "mysql_bind_address"}
    lower_key := lower(key_node.value)
    binding_attrs[_] == lower_key
} else {
    key_node.ir_type == "VariableReference"
    binding_attrs := {"ip", "bind-address", "bind_address", "listen_address", "listenaddr", "bindaddr", "host", "ip_address", "server_address", "mongodb_net_bindip", "mysql_bind_address"}
    lower_key := lower(key_node.value)
    cleaned_key := trim_prefix(lower_key, ":")
    binding_attrs[_] == cleaned_key
}

# Helper to check if value is an unrestricted IP
is_unrestricted_ip(value_node) {
    value_node.ir_type == "String"
    value_node.value == "0.0.0.0"
} else {
    value_node.ir_type == "String"
    value_node.value == "::"
}

# Rule for detecting unrestricted IP in Hash structures (Chef, Puppet) using walk
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk through all nodes to find Hash structures
    walk(parent, [path, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    pair := node.value[_]
    key_node := pair.key
    value_node := pair.value
    
    # Check if this specific key-value pair matches
    is_binding_attribute(key_node)
    is_unrestricted_ip(value_node)
    
    result := {
        "type": "sec_invalid_bind",
        "element": value_node,
        "path": parent.path,
        "description": sprintf("Configuration contains binding to unrestricted IP address %s with key %s (CWE-1327)", [value_node.value, key_node.value])
    }
}

# Rule for detecting unrestricted IP in Variable assignments (Ansible, Puppet, Chef)
# This handles cases where the variable value is a String (Ansible) or Hash (Chef)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all variables in the parent UnitBlock (including nested ones)
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if the variable value is a String with unrestricted IP
    var.value.ir_type == "String"
    is_unrestricted_ip(var.value)
    
    # Check if the variable name indicates it's a binding attribute
    lower_name := lower(var.name)
    binding_pattern := "(bind|listen|ip|address|host|server)"
    regex.match(binding_pattern, lower_name)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": sprintf("Variable '%s' is set to unrestricted IP address %s (CWE-1327)", [var.name, var.value.value])
    }
}

# Rule for detecting unrestricted IP in Variable assignments with Hash values (Chef style)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all variables in the parent UnitBlock (including nested ones)
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if the variable value is a Hash
    var.value.ir_type == "Hash"
    
    # Walk through the hash to find binding attributes
    walk(var.value, [path, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    pair := node.value[_]
    key_node := pair.key
    value_node := pair.value
    
    # Check if this specific key-value pair matches
    is_binding_attribute(key_node)
    is_unrestricted_ip(value_node)
    
    result := {
        "type": "sec_invalid_bind",
        "element": value_node,
        "path": parent.path,
        "description": sprintf("Variable '%s' contains binding to unrestricted IP address %s with key %s (CWE-1327)", [var.name, value_node.value, key_node.value])
    }
}

# Rule for detecting unrestricted IP in AtomicUnit attributes (Puppet, Ansible)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if attribute value is a string with unrestricted IP
    attr.value.ir_type == "String"
    is_unrestricted_ip(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Attribute '%s' is bound to unrestricted IP address %s (CWE-1327)", [attr.name, attr.value.value])
    }
}