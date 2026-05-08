package glitch

import data.glitch_lib

# Detects CWE-284 (Improper Access Control) specifically for network binding to all interfaces (0.0.0.0)
# Handles Chef, Puppet, and Ansible IR structures

Glitch_Analysis[result] {
    # Identify all UnitBlocks (scripts, definitions, etc.)
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Traverse all nodes within the parent to find Attributes or Variables
    walk(parent, [path, node])

    # Check for direct Attribute assignments (e.g., bind_address => '0.0.0.0')
    node.ir_type == "Attribute"
    attr_name_lower := lower(node.name)
    
    # Match bind-related attribute names
    regex.match("(bind|host|ip|addr|address)", attr_name_lower)
    
    # Check if the value is the insecure '0.0.0.0'
    node.value.ir_type == "String"
    node.value.value == "0.0.0.0"

    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Network Binding to All Interfaces - Attribute binds to all network interfaces (0.0.0.0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    # Identify all UnitBlocks
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Traverse all nodes within the parent to find Hash structures (nested configurations)
    walk(parent, [path, node])

    # Check for Hash types (e.g., Chef attributes, Puppet variable hashes)
    node.ir_type == "Hash"
    
    # Iterate through key-value pairs in the hash
    entry := node.value[_]
    
    # Check key is a string (attribute name)
    entry.key.ir_type == "String"
    key_lower := lower(entry.key.value)
    
    # Match bind-related keys
    regex.match("(bind|host|ip|addr|address)", key_lower)
    
    # Check if the value is the insecure '0.0.0.0'
    entry.value.ir_type == "String"
    entry.value.value == "0.0.0.0"

    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Network Binding to All Interfaces - Hash configuration binds to all network interfaces (0.0.0.0). (CWE-284)"
    }
}

Glitch_Analysis[result] {
    # Identify all UnitBlocks
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    # Traverse all nodes to find Variables
    walk(parent, [path, node])
    
    # Check for Variable types
    node.ir_type == "Variable"
    
    # Check variable name for bind-related terms
    name_lower := lower(node.name)
    regex.match("(bind|host|ip|addr|address)", name_lower)
    
    # Check if assigned value is '0.0.0.0'
    node.value.ir_type == "String"
    node.value.value == "0.0.0.0"

    result := {
        "type": "sec_invalid_bind",
        "element": node,
        "path": parent.path,
        "description": "Network Binding to All Interfaces - Variable binds to all network interfaces (0.0.0.0). (CWE-284)"
    }
}