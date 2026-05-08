package glitch

import data.glitch_lib

# Detect CWE-1327: Binding to an Unrestricted IP Address (0.0.0.0)

# Rule 1: Direct variable assignments with unrestricted IP (e.g., Chef attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    
    # Check if the variable name suggests it's an IP binding configuration
    is_ip_binding_name(v.name)
    
    # Check if the value is "0.0.0.0"
    is_unrestricted_ip(v.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - Resources should not bind to 0.0.0.0, allowing unrestricted access. (CWE-1327)"
    }
}

# Rule 2: Attributes in atomic units with unrestricted IP
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check if the attribute name suggests it's an IP binding configuration
    is_ip_binding_name(attr.name)
    
    # Check if the value is "0.0.0.0"
    is_unrestricted_ip(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - Resources should not bind to 0.0.0.0, allowing unrestricted access. (CWE-1327)"
    }
}

# Rule 3: Nested hash structures with unrestricted IP (e.g., Puppet $override_options)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk through all variables to find hash structures
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    
    # Recursively search for hash nodes containing unrestricted IP
    walk(v.value, [path, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    pair := node.value[_]
    is_ip_binding_key(pair.key)
    is_unrestricted_ip(pair.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": v,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - Resources should not bind to 0.0.0.0, allowing unrestricted access. (CWE-1327)"
    }
}

# Rule 4: Nested hash structures in attributes with unrestricted IP
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Recursively search for hash nodes containing unrestricted IP
    walk(attr.value, [path, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    pair := node.value[_]
    is_ip_binding_key(pair.key)
    is_unrestricted_ip(pair.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Binding to an Unrestricted IP Address (0.0.0.0) - Resources should not bind to 0.0.0.0, allowing unrestricted access. (CWE-1327)"
    }
}

# Helper: Check if a value is "0.0.0.0"
is_unrestricted_ip(val) {
    val.ir_type == "String"
    val.value == "0.0.0.0"
}

# Helper: Check if a name suggests it's an IP binding configuration
is_ip_binding_name(name) {
    regex.match("(?i).*(bind|listen|host|ip|address|endpoint|server_address|addr).*", name)
}

# Helper: Check if a hash key indicates a binding configuration
is_ip_binding_key(key) {
    key.ir_type == "String"
    regex.match("(?i).*(bind|listen|host|ip|address|endpoint|server_address|addr).*", key.value)
}

is_ip_binding_key(key) {
    key.ir_type == "VariableReference"
    regex.match("(?i).*(bind|listen|host|ip|address|endpoint|server_address|addr).*", key.value)
}

is_ip_binding_key(key) {
    key.ir_type == "Access"
    walk(key.right, [path, node])
    node.ir_type == "String"
    regex.match("(?i).*(bind|listen|host|ip|address|endpoint|server_address|addr).*", node.value)
}