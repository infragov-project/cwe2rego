package glitch

import data.glitch_lib

# Define common high-privilege users and patterns
high_privilege_users := {"root", "admin", "administrator", "superuser", "sudo", "wheel", "root@*", "root/*"}

# Rule 1: Detect high-privilege remote users in Ansible
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for Ansible-specific attributes
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Look for remote_user attribute with high-privilege value
    attr.name == "remote_user"
    attr.value.ir_type == "String"
    high_privilege_user := high_privilege_users[_]
    contains(attr.value.value, high_privilege_user)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Running with unnecessary high-privilege user (CWE-250)"
    }
}

# Rule 2: Detect high-privilege execution in commands (Puppet exec resources)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for exec resources in Puppet
    node.type == "exec"
    
    # Look for command attribute
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "command"
    
    # Traverse the command value to find high-privilege patterns
    pattern := high_privilege_users[_]
    glitch_lib.traverse(attr.value, pattern)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Running commands with unnecessary high-privilege (CWE-250)"
    }
}

# Rule 3: Detect high-privilege in become/playbook configurations
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check for become configuration in Ansible
    (attr.name == "become" || attr.name == "become_user")
    attr.value.ir_type == "String"
    high_privilege_user := high_privilege_users[_]
    contains(attr.value.value, high_privilege_user)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Using privilege escalation with unnecessary high-privilege user (CWE-250)"
    }
}

# Rule 4: Detect high-privilege in user resources (Puppet/Chef)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check for user resources
    node.type == "user"
    
    # Look for attributes that might indicate high-privilege
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for home directory patterns that might indicate high-privilege
    (attr.name == "home" || attr.name == "directory")
    attr.value.ir_type == "String"
    high_privilege_pattern := {"*/root", "*/admin", "*/administrator"}
    pattern := high_privilege_pattern[_]
    contains(attr.value.value, pattern)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "User resource with high-privilege characteristics (CWE-250)"
    }
}

# Rule 5: Detect SSH connections to root users (generic pattern)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Look for any command or execution that contains SSH to root
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check if attribute value contains SSH pattern to root
    attr.value.ir_type == "String"
    ssh_pattern := "ssh.*root@"
    contains(attr.value.value, ssh_pattern)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "SSH connection to root user (CWE-250)"
    }
}