package glitch

import data.glitch_lib

# Rule for weak password hashing (MD5) in Ansible hash filters
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Detect hash('md5') in attribute values
    attr.value.ir_type == "Sum"
    glitch_lib.traverse(attr.value, "md5")
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak password hashing algorithm (MD5) detected (CWE-326)"
    }
}

# Rule for weak password hashing in Chef (MethodCall to MD5)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Traverse variables directly in the parent unit block
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    # Check if the variable value is a MethodCall with receiver containing MD5
    var.value.ir_type == "MethodCall"
    receiver_code := var.value.receiver.code
    regex.match("(?i).*md5.*", receiver_code)
    
    result := {
        "type": "sec_weak_crypt",
        "element": var,
        "path": parent.path,
        "description": "Weak password hashing algorithm (MD5) detected (CWE-326)"
    }
}

# Rule for weak authentication methods in Puppet (e.g., auth_method => 'md5')
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for auth_method attribute with weak values
    attr.name == "auth_method"
    attr.value.ir_type == "String"
    regex.match("(?i)md5", attr.value.value)
    
    result := {
        "type": "sec_weak_crypt",
        "element": attr,
        "path": parent.path,
        "description": "Weak authentication method (MD5) detected (CWE-326)"
    }
}