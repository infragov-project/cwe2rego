package glitch

import data.glitch_lib

# Define patterns for binding addresses and problematic values
binding_patterns = {"bind_addr", "listen", "host", "ip", "addr", "advertise", "cluster", "vncserver_listen", "bind_address", "listen_address", "ip_address"}
problematic_values = {"0.0.0.0", "0.0.0.0/0", "any", "all_interfaces"}

# Helper function to check if a string matches any of the binding patterns
matches_binding_pattern(str_value) {
    contains(str_value, binding_patterns[_])
}

# Helper function to check if a value is problematic
is_problematic_value(value) {
    value.ir_type == "String"
    problematic_values[value.value]
} else {
    value.ir_type == "VariableReference"
    value.value == "0.0.0.0"
} else {
    value.ir_type == "Boolean"
    value.value == true
}

# Helper function to check if a key-value pair has a binding key and problematic value
check_kv_pair(key, value) {
    key.ir_type == "String"
    matches_binding_pattern(key.value)
    is_problematic_value(value)
}

# Rule for direct String attribute values (like in Ansible modules)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name != ""
    matches_binding_pattern(attr.name)
    is_problematic_value(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Configuration sets binding address to unrestricted IP (0.0.0.0) - Service may be accessible from entire network. (CWE-1327)"
    }
}

# Rule for Variables with Hash values (like Chef example)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    variables := glitch_lib.all_variables(parent)
    var := variables[_]

    # Check if variable value is a Hash
    var.value.ir_type == "Hash"
    hash_entries := var.value.value
    entry := hash_entries[_]

    # Extract key and value from the hash entry
    key := entry.key
    value := entry.value

    check_kv_pair(key, value)

    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Configuration sets binding address to unrestricted IP (0.0.0.0) - Service may be accessible from entire network. (CWE-1327)"
    }
}

# Rule for AtomicUnit attributes with Hash values (like Ansible example)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check if attribute value is a Hash
    attr.value.ir_type == "Hash"
    hash_entries := attr.value.value
    entry := hash_entries[_]

    key := entry.key
    value := entry.value

    check_kv_pair(key, value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Configuration sets binding address to unrestricted IP (0.0.0.0) - Service may be accessible from entire network. (CWE-1327)"
    }
}

# Rule for firewall/security group configurations (direct value)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for firewall/security group patterns
    firewall_patterns = {"cidr", "ingress", "source", "allowed", "remote", "from_port", "to_port", "allow", "security_group", "firewall"}
    contains(attr.name, firewall_patterns[_])

    # Check if value is problematic
    is_problematic_value(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Firewall rule allows unrestricted access (0.0.0.0/0) - Service may be accessible from entire network. (CWE-1327)"
    }
}

# Rule for firewall/security group configurations (array value)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for firewall/security group patterns
    firewall_patterns = {"cidr", "ingress", "source", "allowed", "remote", "from_port", "to_port", "allow", "security_group", "firewall"}
    contains(attr.name, firewall_patterns[_])

    # Check if value is an array containing problematic values
    attr.value.ir_type == "Array"
    array_element := attr.value.value[_]
    is_problematic_value(array_element)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Firewall rule allows unrestricted access (0.0.0.0/0) - Service may be accessible from entire network. (CWE-1327)"
    }
}

# Rule for public exposure attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    # Check for public exposure patterns
    public_patterns = {"public", "internet", "external", "visibility"}
    contains(attr.name, public_patterns[_])

    # Check if value indicates public exposure
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Resource set to public exposure - This may expose the resource to the entire network. (CWE-1327)"
    }
}

# Rule for catching Hash entries in nested structures (like arrays or other hashes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Use walk to find all Hash nodes in the parent
    walk(parent, [_, node])
    node.ir_type == "Hash"
    
    # Iterate over all hash entries
    entry := node.value[_]
    
    # Extract key and value
    key := entry.key
    value := entry.value
    
    check_kv_pair(key, value)

    result := {
        "type": "sec_invalid_bind",
        "element": key,
        "path": parent.path,
        "description": "Configuration sets binding address to unrestricted IP (0.0.0.0) - Service may be accessible from entire network. (CWE-1327)"
    }
}