package glitch

import data.glitch_lib

# Check for open IP strings (0.0.0.0 with optional quotes)
is_open_ip(node) {
    node.ir_type == "String"
    regex.match("^\"?0\\.0\\.0\\.0\"?$", node.value)
}

# Check if name contains bind-related patterns, handling Ruby symbols and various formats
is_bind_var_name(name) {
    lower_name := lower(name)
    exact_match := {"ip", "host", "addr", "address"}
    exact_match[lower_name]
} else {
    lower_name := lower(name)
    contains(lower_name, "bind")
} else {
    lower_name := lower(name)
    contains(lower_name, "listen")
} else {
    lower_name := lower(name)
    regex.match(".*_ip$|.*_host$|.*_addr$|.*_address$", lower_name)
} else {
    lower_name := lower(name)
    regex.match("^:ip$|^:host$|^:addr$|^:address$", lower_name)
}

# Check if a key string matches bind patterns (handles String keys with quotes)
string_key_is_bind(key_str) {
    clean_key := regex.replace(key_str, "^['\"](.+)['\"]$", "$1")
    is_bind_var_name(clean_key)
} else {
    clean_key := regex.replace(key_str, "^:(.+)$", "$1")
    is_bind_var_name(clean_key)
}

# Check if any VariableReference in an Access chain matches bind patterns
access_chain_has_bind(node) {
    node.ir_type == "Access"
    walk(node, [_, item])
    item.ir_type == "VariableReference"
    is_bind_var_name(item.value)
}

# Check if a variable name suggests bind pattern
var_name_is_bind(var_name) {
    is_string(var_name)
    is_bind_var_name(var_name)
} else {
    var_name == "VariableReference"
    false
} else {
    access_chain_has_bind(var_name)
} else {
    is_string(var_name)
    string_key_is_bind(var_name)
}

# Check if a hash entry has bind key and open IP value
hash_has_bind_entry(hash_node) {
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    key_is_bind(entry.key)
    is_open_ip(entry.value)
}

# Check if a key is a bind key
key_is_bind(key) {
    key.ir_type == "VariableReference"
    is_bind_var_name(key.value)
} else {
    key.ir_type == "String"
    string_key_is_bind(key.value)
} else {
    access_chain_has_bind(key)
}

# Find hash entries with bind key and open IP - returns the value node
find_hash_bind_entry(hash_node) = value_node {
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    key_is_bind(entry.key)
    is_open_ip(entry.value)
    value_node := entry.value
}

# Walk nested structures to find any Hash with bind key and open IP
walk_for_bind_open_ip(root) = value_node {
    walk(root, [_, node])
    node.ir_type == "Hash"
    value_node := find_hash_bind_entry(node)
}

# Direct variable with bind name and open IP
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    is_bind_var_name(var.name)
    is_open_ip(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to 0.0.0.0 allowing access from any IP address. (CWE-284)"
    }
}

# Variable with Access/Array notation in name (e.g., default[:redis][:server][:addr])
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    is_string(var.name)
    var.name_value.ir_type == "Access"
    access_chain_has_bind(var.name_value)
    is_open_ip(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to 0.0.0.0 in nested attribute. (CWE-284)"
    }
}

# Variable name contains bracket notation with bind pattern (e.g., default[:redis][:server][:addr])
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    is_string(var.name)
    contains(lower(var.name), "[:")
    regex.match(".*\\[:?(ip|host|addr|address)\\]?", lower(var.name))
    is_open_ip(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to 0.0.0.0 in bracket-style attribute name. (CWE-284)"
    }
}

# Variable with Hash value directly containing bind key and open IP
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    var.value.ir_type == "Hash"
    found_value := find_hash_bind_entry(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": found_value,
        "path": parent.path,
        "description": "Improper Access Control - Service configuration contains bind address 0.0.0.0. (CWE-284)"
    }
}

# Deep nested hash in variable using walk
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    var.value.ir_type == "Hash"
    found_value := walk_for_bind_open_ip(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": found_value,
        "path": parent.path,
        "description": "Improper Access Control - Service configuration contains bind address 0.0.0.0 in nested structure. (CWE-284)"
    }
}

# Check in nested unit_blocks
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nested_blocks := parent.unit_blocks
    block := nested_blocks[_]
    block.variables
    var := block.variables[_]
    
    is_open_ip(var.value)
    
    # Check if variable name is bind pattern OR if its value contains a hash with bind entry
    is_bind_var_name(var.name)
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to 0.0.0.0 in nested block. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nested_blocks := parent.unit_blocks
    block := nested_blocks[_]
    block.variables
    var := block.variables[_]
    
    var.value.ir_type == "Hash"
    found_value := walk_for_bind_open_ip(var.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": found_value,
        "path": parent.path,
        "description": "Improper Access Control - Service configuration contains bind address 0.0.0.0 in nested block structure. (CWE-284)"
    }
}

# Atomic unit attribute with bind name and open IP
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_bind_var_name(attr.name)
    is_open_ip(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Improper Access Control - Service bound to 0.0.0.0 in resource attribute. (CWE-284)"
    }
}

# Atomic unit with Hash value containing bind key and open IP
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.value.ir_type == "Hash"
    found_value := find_hash_bind_entry(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": found_value,
        "path": parent.path,
        "description": "Improper Access Control - Service configuration contains bind address 0.0.0.0 in resource. (CWE-284)"
    }
}

# Deep nested in atomic unit attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.value.ir_type == "Hash"
    found_value := walk_for_bind_open_ip(attr.value)
    
    result := {
        "type": "sec_invalid_bind",
        "element": found_value,
        "path": parent.path,
        "description": "Improper Access Control - Service configuration contains bind address 0.0.0.0 in deeply nested resource. (CWE-284)"
    }
}