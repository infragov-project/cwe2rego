package glitch

import data.glitch_lib

# Define bind address keywords and dangerous values
bind_keywords := {"bind_address", "listen_address", "ip_address", "host", "server_address", "endpoint", "src", "addr", "ip", "bind_ip", "bind", "conf_bind", "mongodb_net_bindip", "mysql_bind_address"}
dangerous_values := {"0.0.0.0", "::"}

# Helper function to check if a key matches bind keywords (without using 'some ... in ...')
matches_bind_keyword(key_expr) := result {
    key_expr.ir_type == "String"
    key_str := key_expr.value
    key_lower := lower(key_str)
    # Check if key contains any bind keyword (case-insensitive)
    count({kw | kw := bind_keywords[_]; contains(lower(kw), key_lower)}) > 0
    result := true
} else {
    key_expr.ir_type == "VariableReference"
    key_str := key_expr.value
    key_lower := lower(key_str)
    count({kw | kw := bind_keywords[_]; contains(lower(kw), key_lower)}) > 0
    result := true
} else {
    result := false
}

# Helper function to check if a value is dangerous (0.0.0.0 or ::)
is_dangerous_value(value_expr) := result {
    value_expr.ir_type == "String"
    value_expr.value == dangerous_values[_]
    result := true
} else {
    result := false
}

# Rule 1: Check variables with direct dangerous values (Ansible case, Chef attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if variable name matches bind keywords (case-insensitive)
    var_name_lower := lower(var.name)
    count({kw | kw := bind_keywords[_]; contains(lower(kw), var_name_lower)}) > 0
    
    # Check if value is dangerous
    is_dangerous_value(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var.value,
        "path": parent.path,
        "description": "Service binding to unrestricted IP address - This may expose the service to all networks. (CWE-1327)"
    }
}

# Rule 2: Check hash key-value pairs where key matches bind keywords and value is dangerous
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if variable value is a hash
    var.value.ir_type == "Hash"
    
    # Walk through hash pairs
    walk(var.value, [path, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    pair := node.value[_]
    
    # Check if key matches bind keywords
    matches_bind_keyword(pair.key)
    
    # Check if value is dangerous
    is_dangerous_value(pair.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": pair.value,
        "path": parent.path,
        "description": "Service binding to unrestricted IP address - This may expose the service to all networks. (CWE-1327)"
    }
}

# Rule 3: Check attributes in atomic units (Puppet case)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if attribute name matches bind keywords (case-insensitive)
    attr_name_lower := lower(attr.name)
    count({kw | kw := bind_keywords[_]; contains(lower(kw), attr_name_lower)}) > 0
    
    # Check if value is dangerous
    is_dangerous_value(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr.value,
        "path": parent.path,
        "description": "Service binding to unrestricted IP address - This may expose the service to all networks. (CWE-1327)"
    }
}

# Rule 4: Check nested hash structures (Chef mongodb_options case)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if variable value is a hash
    var.value.ir_type == "Hash"
    
    # Walk through nested hash structures
    walk(var.value, [path, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    pair := node.value[_]
    
    # For nested hashes, check if the key is a bind keyword and value is dangerous
    # This handles cases like mongodb_options with :ip => "0.0.0.0"
    matches_bind_keyword(pair.key)
    is_dangerous_value(pair.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": pair.value,
        "path": parent.path,
        "description": "Service binding to unrestricted IP address - This may expose the service to all networks. (CWE-1327)"
    }
}