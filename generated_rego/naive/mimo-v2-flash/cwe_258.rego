package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check unit block attributes (like Puppet variable defaults)
    attr := parent.attributes[_]
    
    password_patterns := {"password", "pwd", "pass", "secret", "key", "token", "credential"}
    contains(attr.name, password_patterns[_])
    
    attr.value.ir_type == "String"
    regex.match("^(\\s*)$", attr.value.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - The configuration explicitly sets a password field to an empty string. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check unit block attributes for null values
    attr := parent.attributes[_]
    
    password_patterns := {"password", "pwd", "pass", "secret", "key", "token", "credential"}
    contains(attr.name, password_patterns[_])
    
    attr.value.ir_type == "Null"

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - The configuration sets a password field to null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables (like Chef attributes)
    variable := parent.variables[_]
    
    password_patterns := {"password", "pwd", "pass", "secret", "key", "token", "credential"}
    contains(variable.name, password_patterns[_])
    
    variable.value.ir_type == "Null"

    result := {
        "type": "sec_empty_pass",
        "element": variable,
        "path": parent.path,
        "description": "Empty password in configuration file - The configuration sets a password variable to null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check attributes within atomic units
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    password_patterns := {"password", "pwd", "pass", "secret", "key", "token", "credential"}
    contains(attr.name, password_patterns[_])
    
    attr.value.ir_type == "String"
    regex.match("^(\\s*)$", attr.value.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - The configuration explicitly sets a password field to an empty string. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check attributes within atomic units for null values
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    password_patterns := {"password", "pwd", "pass", "secret", "key", "token", "credential"}
    contains(attr.name, password_patterns[_])
    
    attr.value.ir_type == "Null"

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - The configuration sets a password field to null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check Hash values within atomic units (like Ansible nested structures)
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Look for hash attributes that might contain password fields
    attr.value.ir_type == "Hash"
    
    # Extract password fields from hash
    password_patterns := {"password", "pwd", "pass", "secret", "key", "token", "credential"}
    hash_field := attr.value.value[_]
    hash_field.key.ir_type == "String"
    contains(hash_field.key.value, password_patterns[_])
    
    # Check if the password field has empty value
    hash_field.value.ir_type == "Null"

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - The configuration sets a password field to null in nested structure. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check Hash values within atomic units for empty strings
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Look for hash attributes that might contain password fields
    attr.value.ir_type == "Hash"
    
    # Extract password fields from hash
    password_patterns := {"password", "pwd", "pass", "secret", "key", "token", "credential"}
    hash_field := attr.value.value[_]
    hash_field.key.ir_type == "String"
    contains(hash_field.key.value, password_patterns[_])
    
    # Check if the password field has empty string value
    hash_field.value.ir_type == "String"
    regex.match("^(\\s*)$", hash_field.value.value)

    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - The configuration sets a password field to an empty string in nested structure. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check Hash values within atomic units for empty strings (alternative approach for Ansible)
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Look for hash attributes that might contain password fields
    attr.value.ir_type == "Hash"
    
    # Get all attributes from the hash
    hash_attrs := glitch_lib.all_attributes(attr.value)
    hash_attr := hash_attrs[_]
    
    password_patterns := {"password", "pwd", "pass", "secret", "key", "token", "credential"}
    contains(hash_attr.name, password_patterns[_])
    
    hash_attr.value.ir_type == "String"
    regex.match("^(\\s*)$", hash_attr.value.value)

    result := {
        "type": "sec_empty_pass",
        "element": hash_attr,
        "path": parent.path,
        "description": "Empty password in configuration file - The configuration sets a password field to an empty string in nested structure. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check Hash values within atomic units for null values (alternative approach for Ansible)
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Look for hash attributes that might contain password fields
    attr.value.ir_type == "Hash"
    
    # Get all attributes from the hash
    hash_attrs := glitch_lib.all_attributes(attr.value)
    hash_attr := hash_attrs[_]
    
    password_patterns := {"password", "pwd", "pass", "secret", "key", "token", "credential"}
    contains(hash_attr.name, password_patterns[_])
    
    hash_attr.value.ir_type == "Null"

    result := {
        "type": "sec_empty_pass",
        "element": hash_attr,
        "path": parent.path,
        "description": "Empty password in configuration file - The configuration sets a password field to null in nested structure. (CWE-258)"
    }
}