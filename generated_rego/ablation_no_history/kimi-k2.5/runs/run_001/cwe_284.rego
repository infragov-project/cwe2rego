package glitch

import data.glitch_lib

import future.keywords.in

# Network-related attribute/variable name patterns
network_name_patterns := ["bind", "listen", "host", "address", "ip", "interface", "bindip", "bind_ip", "bindaddress", "bind_address", "bindaddr", "listen_address", "listeninterface", "listen_ip", "listenaddr", "source", "destination", "cidr", "subnet", "network", "addr"]

# Open network binding values (0.0.0.0, ::, etc.)
open_bind_pattern := "(?i)^\\s*(0\\.0\\.0\\.0(/0)?|::(/0)?|\\*|all|any|0000:0000:0000:0000:0000:0000:0000:0000)\\s*$"

# Helper to check if a feature is in a set
network_name_matches(name) {
    some pattern in network_name_patterns
    regex.match(sprintf(".*%s.*", [pattern]), lower(name))
}

# Check if string value matches open bind pattern
is_open_bind_string(s) {
    s.ir_type == "String"
    regex.match(open_bind_pattern, s.value)
}

# Recursively check for open bind in value using walk - handles nested structures like Hash in Hash
has_open_bind_in_value(root) {
    walk(root, [_, node])
    is_open_bind_string(node)
}

# Check variables in unit blocks - including nested unit blocks
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk through all nested unit blocks as well
    walk(parent, [_, node])
    
    # Check if node is a Variable directly in parent or in nested structures
    node.ir_type == "Variable"
    network_name_matches(node.name)
    has_open_bind_in_value(node.value)

    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Improper Access Control - Network service bound to 0.0.0.0 or equivalent, exposing it to all network interfaces. (CWE-284)"
    }
}

# Check attributes in atomic units
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    network_name_matches(attr.name)
    has_open_bind_in_value(attr.value)

    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Network service bound to 0.0.0.0 or equivalent, exposing it to all network interfaces. (CWE-284)"
    }
}

# Check for open bind in Hash keys as well (for cases like ':ip' => '0.0.0.0' or 'bind-address' => '0.0.0.0')
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk everything to find Hash structures
    walk(parent, [_, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    some pair in node.value
    
    # Check if key matches network pattern
    pair.key.ir_type == "VariableReference"
    network_name_matches(pair.key.value)
    
    # Check if value is open bind
    has_open_bind_in_value(pair.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": pair,
        "path": parent.path,
        "description": "Improper Access Control - Network service bound to 0.0.0.0 or equivalent, exposing it to all network interfaces. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk everything to find Hash structures
    walk(parent, [_, node])
    node.ir_type == "Hash"
    
    # Check each key-value pair in the hash
    some pair in node.value
    
    # Check if key matches network pattern - also handle String keys
    pair.key.ir_type == "String"
    network_name_matches(pair.key.value)
    
    # Check if value is open bind
    has_open_bind_in_value(pair.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": pair,
        "path": parent.path,
        "description": "Improper Access Control - Network service bound to 0.0.0.0 or equivalent, exposing it to all network interfaces. (CWE-284)"
    }
}

# Check for open bind in nested Hash structures (Hash within Hash)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk to find nested Hash structures
    walk(parent, [_, outer_hash])
    outer_hash.ir_type == "Hash"
    
    some outer_pair in outer_hash.value
    outer_pair.value.ir_type == "Hash"
    
    inner_hash := outer_pair.value
    
    some inner_pair in inner_hash.value
    
    # Check if inner key matches network pattern
    inner_pair.key.ir_type == "String"
    network_name_matches(inner_pair.key.value)
    
    # Check if inner value is open bind
    has_open_bind_in_value(inner_pair.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": inner_pair,
        "path": parent.path,
        "description": "Improper Access Control - Network service bound to 0.0.0.0 or equivalent, exposing it to all network interfaces. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk to find nested Hash structures
    walk(parent, [_, outer_hash])
    outer_hash.ir_type == "Hash"
    
    some outer_pair in outer_hash.value
    outer_pair.value.ir_type == "Hash"
    
    inner_hash := outer_pair.value
    
    some inner_pair in inner_hash.value
    
    # Check if inner key matches network pattern - VariableReference variant
    inner_pair.key.ir_type == "VariableReference"
    network_name_matches(inner_pair.key.value)
    
    # Check if inner value is open bind
    has_open_bind_in_value(inner_pair.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": inner_pair,
        "path": parent.path,
        "description": "Improper Access Control - Network service bound to 0.0.0.0 or equivalent, exposing it to all network interfaces. (CWE-284)"
    }
}