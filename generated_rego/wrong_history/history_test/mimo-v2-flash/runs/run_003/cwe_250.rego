package glitch

import data.glitch_lib

# Rule for overly permissive IAM/RBAC policies
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "Effect"
    attr.value.ir_type == "String"
    attr.value.value == "Allow"
    
    # Check for wildcard actions and resources
    some action_attr in attrs
    action_attr.name == "Action"
    action_attr.value.ir_type == "String"
    action_attr.value.value == "*"
    
    some resource_attr in attrs
    resource_attr.name == "Resource"
    resource_attr.value.ir_type == "String"
    resource_attr.value.value == "*"
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive IAM policy - Grants blanket permissions beyond the principle of least privilege. (CWE-250)"
    }
}

# Rule for privileged containers
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "privileged"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged container execution - Containers running with elevated privileges increase attack surface. (CWE-250)"
    }
}

# Rule for root user execution
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    (attr.name == "runAsUser" || attr.name == "runAsGroup")
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Root user execution - Processes running as root increase security risks. (CWE-250)"
    }
}

# Rule for overly permissive capabilities
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "capabilities"
    attr.value.ir_type == "Array"
    
    # Check if array contains "ALL" capability
    some cap in attr.value.value
    cap.ir_type == "String"
    cap.value == "ALL"
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive Linux capabilities - Containers should not have ALL capabilities. (CWE-250)"
    }
}

# Rule for unrestricted filesystem permissions
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "permissions"
    attr.value.ir_type == "String"
    regex.match("(?:^0?777$)|(?:(?:^|(?:ugo)|o|a)\\+[rwx]{3})", attr.value.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted filesystem permissions - Files should not have full permissions to every user. (CWE-250)"
    }
}

# Rule for bypassed privilege dropping
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for script commands that use sudo but don't drop privileges
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "command"
    attr.value.ir_type == "String"
    regex.match("sudo", attr.value.value)
    not regex.match("sudo -u", attr.value.value)
    not regex.match("su ", attr.value.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Bypassed privilege dropping - Scripts use sudo but don't drop privileges after execution. (CWE-250)"
    }
}