package glitch

import data.glitch_lib

# Keywords that indicate a credential field
credential_fields := {"password", "secret", "key", "token", "api_key", "access_key", "secret_key", "ssh_key", "private_key", "client_secret", "shared_secret", "credential", "pwd"}

# Check if a string value looks like a hardcoded secret value
is_hardcoded_secret_value(val) {
    val != ""
    regex.match("(?i)^(changeme|admin|password|123456|secret|root|letmein|welcome)$", val)
} else {
    val != ""
    regex.match("^[0-9a-fA-F]{32,}$", val)
} else {
    val != ""
    regex.match("^[A-Za-z0-9+/]+={0,2}$", val)
    count(val) >= 20
} else {
    val != ""
    regex.match("^\\$[0-9]\\$", val)
}

# Check if value is a secure reference
is_secure_reference(value) {
    value.ir_type == "VariableReference"
} else {
    value.ir_type == "FunctionCall"
    regex.match("(?i).*random.*|.*secret.*", value.name)
} else {
    value.ir_type == "MethodCall"
    regex.match("(?i).*random.*|.*secret.*", value.method)
}

# Check if a name suggests a credential field
is_credential_field(name) {
    some field in credential_fields
    regex.match(sprintf("(?i).*%s.*", [field]), name)
}

# Main detection for variables (Ansible, Chef, Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    is_credential_field(var.name)
    
    var.value.ir_type == "String"
    var.value.value != ""
    is_hardcoded_secret_value(var.value.value)
    not is_secure_reference(var.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": var,
        "path": parent.path,
        "description": sprintf("Hardcoded credential in variable '%s' (CWE-798)", [var.name])
    }
}

# Main detection for attributes (Ansible, Chef, Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_credential_field(attr.name)
    
    attr.value.ir_type == "String"
    attr.value.value != ""
    is_hardcoded_secret_value(attr.value.value)
    not is_secure_reference(attr.value)
    
    result := {
        "type": "sec_hard_secr",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Hardcoded credential in attribute '%s' (CWE-798)", [attr.name])
    }
}

# Detection for nested credentials in Hash structures
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "String"
    node.value != ""
    
    is_hardcoded_secret_value(node.value)
    
    # Check if path contains a credential keyword
    path_has_credential := false
    path_has_credential = true
    {
        walk(parent, [path, n])
        n.ir_type == "String"
        is_credential_field(n.value)
    }
    
    path_has_credential
    not is_secure_reference(node)
    
    result := {
        "type": "sec_hard_secr",
        "element": node,
        "path": parent.path,
        "description": "Hardcoded credential in nested structure (CWE-798)"
    }
}

# Detection for nested credentials in complex attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.value.ir_type == "Hash"
    
    walk(attr.value, [path, n])
    n.ir_type == "String"
    n.value != ""
    
    # The immediate parent key should be a credential field
    count(path) > 0
    last_key := path[count(path)-1]
    last_key.ir_type == "String"
    is_credential_field(last_key.value)
    
    is_hardcoded_secret_value(n.value)
    not is_secure_reference(n)
    
    result := {
        "type": "sec_hard_secr",
        "element": n,
        "path": parent.path,
        "description": sprintf("Hardcoded credential in attribute '%s' (CWE-798)", [attr.name])
    }
}