package glitch

import data.glitch_lib

# Set of keywords indicating passwords or secrets
password_keywords := {"password", "pwd", "pass", "secret", "key", "token", "api_key", "shared_secret", "admin_password", "root_password", "db_password", "sha512_password"}

# Check if a name contains password-related keywords
is_password_name(name) {
    lower_name := lower(name)
    password_keywords[_] == lower_name
}

# Check if a value is a hardcoded string (not a variable reference or function call)
is_hardcoded_string(value) {
    value.ir_type == "String"
    count(value.value) > 0
}

# Function to recursively find all KeyValue nodes in a value that have password-related keys and hardcoded string values
find_password_keyvalues(value) = matches {
    matches := {kv |
        walk(value, [path, node])
        node.ir_type == "KeyValue"
        is_password_name(node.name)
        is_hardcoded_string(node.value)
        kv := node
    }
}

# Rule for Variables (Ansible, Chef, Puppet) - Top-level
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get variables from the parent unit block
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if the variable name indicates a password
    is_password_name(var.name)
    
    # Check if the value is a hard-coded string
    is_hardcoded_string(var.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": var,
        "path": parent.path,
        "description": "Use of hard-coded password in variable - Passwords should not be hardcoded in IaC scripts. (CWE-259)"
    }
}

# Rule for Attributes (Atomic Units) - Top-level
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get atomic units from the parent
    atomic_units := glitch_lib.all_atomic_units(parent)
    atom_node := atomic_units[_]
    
    # Get attributes from the atomic unit
    attrs := glitch_lib.all_attributes(atom_node)
    attr := attrs[_]
    
    # Check if the attribute name indicates a password
    is_password_name(attr.name)
    
    # Check if the value is a hard-coded string
    is_hardcoded_string(attr.value)
    
    result := {
        "type": "sec_hard_pass",
        "element": attr,
        "path": parent.path,
        "description": "Use of hard-coded password in resource attribute - Passwords should not be hardcoded in IaC scripts. (CWE-259)"
    }
}

# Rule for Nested Structures in Variables (Hash/Array) - Recursive
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Find password keyvalues in nested structures
    keyvalues := find_password_keyvalues(var.value)
    count(keyvalues) > 0
    kv := keyvalues[_]
    
    result := {
        "type": "sec_hard_pass",
        "element": kv,
        "path": parent.path,
        "description": "Use of hard-coded password in nested variable structure - Passwords should not be hardcoded in IaC scripts. (CWE-259)"
    }
}

# Rule for Nested Structures in Attributes (Hash/Array) - Recursive
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    atom_node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(atom_node)
    attr := attrs[_]
    
    # Find password keyvalues in nested structures
    keyvalues := find_password_keyvalues(attr.value)
    count(keyvalues) > 0
    kv := keyvalues[_]
    
    result := {
        "type": "sec_hard_pass",
        "element": kv,
        "path": parent.path,
        "description": "Use of hard-coded password in nested attribute structure - Passwords should not be hardcoded in IaC scripts. (CWE-259)"
    }
}