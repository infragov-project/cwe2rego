package glitch

import data.glitch_lib

# Definition of high-privilege actions and patterns (CWE-250)
high_privilege_patterns := {"iam:*", "secretsmanager:*", "AdministratorAccess", "Owner", "root", "privileged", "runAsUser.*0", "runAsGroup.*0", "privileged:.*true", "SYS_ADMIN", "CAP_SYS_ADMIN"}

# Check if a string value matches high-privilege patterns
check_high_privilege(value) {
    value.ir_type == "String"
    regex.match("(?i).*(iam:\\*|secretsmanager:\\*|AdministratorAccess|Owner|root|privileged|runAsUser\\.\\*0|runAsGroup\\.\\*0|privileged:.*true|SYS_ADMIN|CAP_SYS_ADMIN).*", value.value)
}

# Check for wildcard permissions (e.g., "*") in sensitive contexts
check_wildcard(value) {
    value.ir_type == "String"
    value.value == "*"
} else {
    value.ir_type == "String"
    regex.match("(?i)\\*", value.value)
}

# Check for overly permissive file permissions (e.g., 777, 666, 775)
check_file_permission(value) {
    value.ir_type == "String"
    regex.match("(?:^0?777$)|(?:^0?666$)|(?:(?:^|(?:ugo)|o|a)\\+[rwx]{3})", value.value)
} else {
    value.ir_type == "Integer"
    value.value == 777
}

check_file_permission(value) {
    value.ir_type == "Integer"
    value.value == 666
}

check_file_permission(value) {
    value.ir_type == "Integer"
    value.value == 775
}

# Rule: Detect Privileged Execution Contexts
# Looks for attributes indicating privileged execution (e.g., runAsUser: 0, privileged: true)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for standard resource types that might have security contexts
    endswith(node.type, data.security.shell_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for specific security attributes
    attr.name == "runAsUser"
    check_high_privilege(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged execution context detected - Execution as root or with elevated privileges increases attack surface. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for standard resource types that might have security contexts
    endswith(node.type, data.security.shell_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for specific security attributes
    attr.name == "runAsGroup"
    check_high_privilege(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged execution context detected - Execution as root or with elevated privileges increases attack surface. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for standard resource types that might have security contexts
    endswith(node.type, data.security.shell_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for specific security attributes
    attr.name == "privileged"
    check_high_privilege(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged execution context detected - Execution as root or with elevated privileges increases attack surface. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for standard resource types that might have security contexts
    endswith(node.type, data.security.shell_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for specific security attributes
    attr.name == "capabilities"
    check_high_privilege(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged execution context detected - Execution as root or with elevated privileges increases attack surface. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for standard resource types that might have security contexts
    endswith(node.type, data.security.shell_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for specific security attributes
    attr.name == "securityContext"
    check_high_privilege(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged execution context detected - Execution as root or with elevated privileges increases attack surface. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for standard resource types that might have security contexts
    endswith(node.type, data.security.shell_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for specific security attributes
    attr.name == "runAsRoot"
    check_high_privilege(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged execution context detected - Execution as root or with elevated privileges increases attack surface. (CWE-250)"
    }
}

# Rule: Detect Overly Permissive IAM Policies and Wildcards
# Looks for wildcard permissions or high-privilege actions in policy statements
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for IAM policy resources
    endswith(node.type, data.security.iam_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Look for Action attributes that might contain wildcards or high-privilege actions
    attr.name == "Action"
    check_wildcard(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive IAM policy detected - Use of wildcards or high-privilege actions violates least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for IAM policy resources
    endswith(node.type, data.security.iam_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Look for Action attributes that might contain wildcards or high-privilege actions
    attr.name == "Action"
    check_high_privilege(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive IAM policy detected - Use of wildcards or high-privilege actions violates least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for IAM policy resources
    endswith(node.type, data.security.iam_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Look for Resource attributes that might contain wildcards or high-privilege actions
    attr.name == "Resource"
    check_wildcard(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive IAM policy detected - Use of wildcards or high-privilege actions violates least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for IAM policy resources
    endswith(node.type, data.security.iam_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Look for Resource attributes that might contain wildcards or high-privilege actions
    attr.name == "Resource"
    check_high_privilege(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive IAM policy detected - Use of wildcards or high-privilege actions violates least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for IAM policy resources
    endswith(node.type, data.security.iam_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Look for Effect attributes that might contain wildcards or high-privilege actions
    attr.name == "Effect"
    check_wildcard(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive IAM policy detected - Use of wildcards or high-privilege actions violates least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for IAM policy resources
    endswith(node.type, data.security.iam_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Look for Effect attributes that might contain wildcards or high-privilege actions
    attr.name == "Effect"
    check_high_privilege(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive IAM policy detected - Use of wildcards or high-privilege actions violates least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for IAM policy resources
    endswith(node.type, data.security.iam_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Look for Principal attributes that might contain wildcards or high-privilege actions
    attr.name == "Principal"
    check_wildcard(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive IAM policy detected - Use of wildcards or high-privilege actions violates least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for IAM policy resources
    endswith(node.type, data.security.iam_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Look for Principal attributes that might contain wildcards or high-privilege actions
    attr.name == "Principal"
    check_high_privilege(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive IAM policy detected - Use of wildcards or high-privilege actions violates least privilege. (CWE-250)"
    }
}

# Rule: Detect Excessive File/Directory Permissions
# Looks for file resource permissions that are too permissive
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for file/resource types that handle permissions
    endswith(node.type, data.security.file_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for permission-related attributes
    attr.name == "mode"
    check_file_permission(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive file/directory permissions detected - Overly permissive permissions can lead to unauthorized access. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for file/resource types that handle permissions
    endswith(node.type, data.security.file_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for permission-related attributes
    attr.name == "permissions"
    check_file_permission(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive file/directory permissions detected - Overly permissive permissions can lead to unauthorized access. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for file/resource types that handle permissions
    endswith(node.type, data.security.file_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for permission-related attributes
    attr.name == "permission"
    check_file_permission(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive file/directory permissions detected - Overly permissive permissions can lead to unauthorized access. (CWE-250)"
    }
}

# Rule: Detect Unnecessary Privileged Operations
# Looks for execution of administrative commands in routine tasks
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for shell or command execution resources
    endswith(node.type, data.security.shell_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for command attributes
    attr.name == "command"
    
    # Check for administrative commands
    attr.value.ir_type == "String"
    regex.match("(?i).*(mount|apt-get|systemctl|sudo|su|chmod|chown|useradd|groupadd).*", attr.value.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Unnecessary privileged operation detected - Administrative commands should not be used for routine tasks. (CWE-250)"
    }
}

# Rule: Detect Insecure Service/Role Configurations
# Looks for roles or services with excessive privileges
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for role or service definition resources
    endswith(node.type, data.security.role_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for role name or policy attributes
    attr.name == "role"
    check_high_privilege(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Insecure service/role configuration detected - Role or service has excessive privileges beyond requirements. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for role or service definition resources
    endswith(node.type, data.security.role_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for role name or policy attributes
    attr.name == "name"
    check_high_privilege(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Insecure service/role configuration detected - Role or service has excessive privileges beyond requirements. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for role or service definition resources
    endswith(node.type, data.security.role_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for role name or policy attributes
    attr.name == "managed_policy_arns"
    check_high_privilege(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Insecure service/role configuration detected - Role or service has excessive privileges beyond requirements. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for role or service definition resources
    endswith(node.type, data.security.role_resources[_])
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for role name or policy attributes
    attr.name == "policy"
    check_high_privilege(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Insecure service/role configuration detected - Role or service has excessive privileges beyond requirements. (CWE-250)"
    }
}

# Additional rule to detect privileged user settings in attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for user attributes that might be set to root
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Look for user attributes that might be set to root
    attr.name == "user"
    attr.value.ir_type == "String"
    attr.value.value == "root"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged user detected - Running as root or Administrator increases attack surface. (CWE-250)"
    }
}

# Additional rule to detect privileged user settings in variables (Ansible)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for become_user attributes in Ansible
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for become_user attributes that might be set to root
    attr.name == "become_user"
    attr.value.ir_type == "String"
    attr.value.value == "root"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged user detected - Running as root or Administrator increases attack surface. (CWE-250)"
    }
}

# Additional rule to detect privileged user settings in variables (Chef)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for user attributes in Chef
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for user attributes that might be set to root
    attr.name == "user"
    attr.value.ir_type == "String"
    attr.value.value == "root"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged user detected - Running as root or Administrator increases attack surface. (CWE-250)"
    }
}

# Additional rule to detect privileged user settings in variables (Puppet)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for user attributes in Puppet
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for user attributes that might be set to root
    attr.name == "user"
    attr.value.ir_type == "String"
    attr.value.value == "root"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged user detected - Running as root or Administrator increases attack surface. (CWE-250)"
    }
}