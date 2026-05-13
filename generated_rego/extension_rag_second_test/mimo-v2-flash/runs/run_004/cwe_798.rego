package glitch

import data.glitch_lib

# Keywords indicating sensitive data
credential_keywords := {"password", "secret", "token", "key", "credential", "auth"}

# Check if a name matches credential keywords
is_credential_name(name) {
    lower_name := lower(name)
    some kw
    credential_keywords[kw]
    regex.match(sprintf(".*%s.*", [kw]), lower_name)
}

# Check if the value is a static string (not a variable reference or function)
is_static_string(value_expr) {
    value_expr.ir_type == "String"
}

# Rule 1: Detect hardcoded credentials in Variables (Ansible, Chef, Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all variables from the parent unit block
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if the variable name indicates a credential
    is_credential_name(var.name)
    
    # Check if the value is a static string
    is_static_string(var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": "Hardcoded credential in variable definition (CWE-798)."
    }
}

# Rule 2: Detect hardcoded credentials in Attributes (Puppet class parameters, Chef attributes)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Get all attributes from the parent unit block
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check if the attribute name indicates a credential
    is_credential_name(attr.name)
    
    # Check if the value is a static string
    is_static_string(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded credential in attribute definition (CWE-798)."
    }
}

# Rule 3: Detect hardcoded credentials in Atomic Units (Ansible tasks, Chef resources, Puppet resources)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Get all attributes from the atomic unit
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if the attribute name indicates a credential
    is_credential_name(attr.name)
    
    # Check if the value is a static string
    is_static_string(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": "Hardcoded credential in resource definition (CWE-798)."
    }
}

# Rule 4: Detect hardcoded credentials in nested structures (Hash/Array)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Walk through all nodes in the parent unit block
    walk(parent, [path, node])
    
    # Check for Hash nodes
    node.ir_type == "Hash"
    
    # Iterate through key-value pairs
    some i
    key_expr := node.value[i].key
    value_expr := node.value[i].value
    
    # Check if key is a string and contains credential keywords
    key_expr.ir_type == "String"
    is_credential_name(key_expr.value)
    
    # Check if value is a static string
    is_static_string(value_expr)
    
    result := {
        "type": "sec_hard_secr",
        "element": value_expr,
        "path": parent.path,
        "description": "Hardcoded credential in nested configuration (CWE-798)."
    }
}