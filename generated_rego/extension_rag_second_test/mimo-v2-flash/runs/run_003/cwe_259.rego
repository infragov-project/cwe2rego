package glitch

import data.glitch_lib

# CWE-259: Use of Hard-coded Password
# Detects hardcoded credentials in Variables (Ansible, Chef, Puppet) and Attributes (Ansible).

# Set of keywords indicating secrets (case-insensitive)
secret_keywords := {"password", "secret", "token", "credential", "pass", "key", "api_key", "shared_secret", "sha512_password"}

# Helper to check if a key name suggests a secret
is_secret_key(key_name) {
    lower_key := lower(key_name)
    secret_keywords[_] == lower_key
}

# Helper to check if a value is a hardcoded string literal (not a reference)
is_hardcoded_literal(value) {
    value.ir_type == "String"
    count(value.value) > 0
}

# Main rule: Detect hardcoded credentials in Variables (e.g., Ansible, Chef)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk to find any Variable node in the tree
    walk(parent, [path, node])
    node.ir_type == "Variable"
    
    # Check if the variable name indicates a secret
    is_secret_key(node.name)
    
    # Ensure the value is a hardcoded string literal
    is_hardcoded_literal(node.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Variable contains a static credential. (CWE-259)"
    }
}

# Main rule: Detect hardcoded credentials in Attributes (Ansible)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Walk to find any Attribute node in the atomic unit
    walk(node, [path, attr])
    attr.ir_type == "Attribute"
    
    # Check if the attribute name indicates a secret
    is_secret_key(attr.name)
    
    # Ensure the value is a hardcoded string literal
    is_hardcoded_literal(attr.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Attribute contains a static credential. (CWE-259)"
    }
}

# Rule for nested Hash keys (Ansible YAML structures)
# Detects "password: value" inside nested dictionaries
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check Variables
    walk(parent, [path, node])
    node.ir_type == "Variable"
    
    # Recursively check the value of the variable for Hash structures
    walk(node.value, [value_path, value_node])
    
    # Identify a Hash key that matches secret keywords
    value_node.ir_type == "String"
    is_secret_key(value_node.value)
    
    # Verify this string is a key in a Hash by checking the parent structure
    # and ensuring the associated value is a hardcoded string
    node.value.ir_type == "Hash"
    associated_value := node.value.value[value_node.value]
    
    # Check if the associated value exists and is a hardcoded literal
    associated_value.ir_type == "String"
    is_hardcoded_literal(associated_value)
    
    result := {
        "type": "sec_hard_pass",
        "element": value_node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Nested field contains a static credential. (CWE-259)"
    }
}

# Rule for nested Hash keys in Attributes (Ansible YAML structures)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check Attributes
    walk(node, [path, attr])
    attr.ir_type == "Attribute"
    
    # Recursively check the value of the attribute for Hash structures
    walk(attr.value, [value_path, value_node])
    
    # Identify a Hash key that matches secret keywords
    value_node.ir_type == "String"
    is_secret_key(value_node.value)
    
    # Verify this string is a key in a Hash
    attr.value.ir_type == "Hash"
    associated_value := attr.value.value[value_node.value]
    
    # Check if the associated value exists and is a hardcoded literal
    associated_value.ir_type == "String"
    is_hardcoded_literal(associated_value)
    
    result := {
        "type": "sec_hard_pass",
        "element": value_node,
        "path": parent.path,
        "description": "Use of Hard-coded Password - Nested attribute contains a static credential. (CWE-259)"
    }
}