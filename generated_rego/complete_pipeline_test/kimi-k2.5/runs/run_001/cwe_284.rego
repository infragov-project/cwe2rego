package glitch

import data.glitch_lib
import future.keywords.in

# Check for open network binding (0.0.0.0 or ::)
is_open_network_bind(value) {
    value.ir_type == "String"
    cleaned := regex.replace(value.value, "^[\"']+|[\"']+$", "")
    regex.match("^(0\\.0\\.0\\.0|::|0\\.0\\.0\\.0/0|::/0)$", cleaned)
}

# Check if name suggests network binding context
is_network_bind_name(name) {
    regex.match("(?i)(bind|listen|address|ip|addr|host|interface|socket)", name)
}

# Extract key name from various key node types
extract_key_name(key_node) = name {
    key_node.ir_type == "String"
    name := key_node.value
} else = name {
    key_node.ir_type == "VariableReference"
    raw := key_node.value
    startswith(raw, ":")
    name := substring(raw, 1, -1)
} else = name {
    key_node.ir_type == "VariableReference"
    name := key_node.value
}

# Check if a Hash has a network-related key (we'll check values separately with walk)
hash_has_network_key(hash_node) {
    some k, _ in hash_node.value
    is_network_bind_name(extract_key_name(k))
}

# Check Variable with network name containing open bind
variable_has_open_bind(var_node) {
    is_network_bind_name(var_node.name)
    var_node.value.ir_type == "String"
    is_open_network_bind(var_node.value)
}

# Walk all variables and find ones with network names containing open binds
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    some var in parent.variables
    var.ir_type == "Variable"
    is_network_bind_name(var.name)
    
    # Find all String descendants of this variable's value
    walk(var.value, [_, node])
    node.ir_type == "String"
    is_open_network_bind(node)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Network service bound to all interfaces (0.0.0.0), allowing access from any host. (CWE-284)"
    }
}

# Walk all attributes in atomic units
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    some au in atomic_units
    
    some attr in au.attributes
    is_network_bind_name(attr.name)
    
    walk(attr.value, [_, node])
    node.ir_type == "String"
    is_open_network_bind(node)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Network service bound to all interfaces (0.0.0.0), allowing access from any host. (CWE-284)"
    }
}

# Find Hash entries with network-related keys containing open binds anywhere in value
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Start from variables that contain Hashes
    some var in parent.variables
    walk(var.value, [_, hash_node])
    hash_node.ir_type == "Hash"
    
    # Check if any key in this hash is network-related and its value contains open bind
    some k, v in hash_node.value
    is_network_bind_name(extract_key_name(k))
    
    walk(v, [_, node])
    node.ir_type == "String"
    is_open_network_bind(node)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Network service bound to all interfaces (0.0.0.0), allowing access from any host. (CWE-284)"
    }
}

# Also check inside atomic unit attributes for Hash structures
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    some au in atomic_units
    
    some attr in au.attributes
    walk(attr.value, [_, hash_node])
    hash_node.ir_type == "Hash"
    
    some k, v in hash_node.value
    is_network_bind_name(extract_key_name(k))
    
    walk(v, [_, node])
    node.ir_type == "String"
    is_open_network_bind(node)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Network service bound to all interfaces (0.0.0.0), allowing access from any host. (CWE-284)"
    }
}

# Also check for any string in the entire structure that matches open bind
# when we can't determine context, but the string itself is suspicious
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk everything and find open binds in any string
    walk(parent, [_, node])
    node.ir_type == "String"
    is_open_network_bind(node)
    
    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Network service bound to all interfaces (0.0.0.0), allowing access from any host. (CWE-284)"
    }
}