package glitch

import data.glitch_lib

# Helper to check if a value contains excessive privilege patterns
has_excessive_privilege(node) {
    glitch_lib.traverse(node, "(?i)(root|admin|administrator|superuser|owner|privileged|all|full|public|cloud-platform|AdministratorAccess|\\*)")
}

# Rule to detect excessive privileges in critical attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    
    # Critical attributes that control privilege levels
    critical_attributes := {"user", "remote_user", "become_user", "runAsUser", "runAsRoot", "privileged", "sudo", "root", "administrator", "superuser", "owner", "scopes", "role", "policy", "acl", "file_permission", "master_username", "superuser", "become", "become_method"}
    
    critical_attributes[attr.name]
    has_excessive_privilege(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive privilege level detected - CWE-250: Execution with Unnecessary Privileges"
    }
}

# Rule to detect excessive privileges in command/script attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_attrs := glitch_lib.all_attributes(parent)
    attr := all_attrs[_]
    
    # Command-related attributes that might contain privilege escalation
    command_attributes := {"command", "shell", "script", "user_data", "startup_script", "cmd", "exec", "creates", "removes", "chdir"}
    
    command_attributes[attr.name]
    has_excessive_privilege(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Command with excessive privilege context - CWE-250: Execution with Unnecessary Privileges"
    }
}

# Rule to detect privilege escalation in container security contexts
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Look for container-related atomic units
    {"container", "pod", "docker_container", "k8s_container"}[node.type]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for privilege escalation in security attributes
    security_attributes := {"privileged", "runAsUser", "runAsRoot", "runAsGroup", "additionalCapabilities", "allowPrivilegeEscalation"}
    security_attributes[attr.name]
    has_excessive_privilege(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container privilege escalation - CWE-250: Execution with Unnecessary Privileges"
    }
}

# Rule to detect privilege escalation in IAM/resource policies
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Look for IAM/policy-related atomic units
    {"iam_binding", "iam_policy", "role", "service_account", "policy"}[node.type]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for excessive permissions in policy documents or role assignments
    policy_attributes := {"role", "policy", "policy_arn", "permissions", "scopes", "members"}
    policy_attributes[attr.name]
    has_excessive_privilege(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "IAM privilege escalation - CWE-250: Execution with Unnecessary Privileges"
    }
}

# Rule to detect privilege escalation in database configurations
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Look for database-related atomic units
    {"database_instance", "database", "db_user", "mysql_user", "postgresql_user"}[node.type]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for excessive database privileges
    db_attributes := {"username", "master_username", "superuser", "privileges", "roles"}
    db_attributes[attr.name]
    has_excessive_privilege(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Database privilege escalation - CWE-250: Execution with Unnecessary Privileges"
    }
}

# Rule to detect privilege escalation in storage configurations
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Look for storage-related atomic units
    {"storage_bucket", "volume", "filesystem", "share"}[node.type]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    # Check for excessive storage permissions
    storage_attributes := {"acl", "permissions", "owner", "group", "user", "uniform_bucket_level_access"}
    storage_attributes[attr.name]
    has_excessive_privilege(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Storage privilege escalation - CWE-250: Execution with Unnecessary Privileges"
    }
}

# Rule to detect privilege escalation in variable definitions
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    all_vars := glitch_lib.all_variables(parent)
    var := all_vars[_]
    
    # Check if variable contains excessive privilege patterns
    has_excessive_privilege(var.value)
    
    result := {
        "type": "sec_def_admin",
        "element": var,
        "path": parent.path,
        "description": "Variable with excessive privilege context - CWE-250: Execution with Unnecessary Privileges"
    }
}

# Rule to detect privilege escalation in conditional statements
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    conditions := glitch_lib.all_conditional_statements(parent)
    cond := conditions[_]
    
    # Check if condition involves privilege checks
    glitch_lib.traverse(cond.condition, "(?i)(root|admin|privileged|sudo|uid0|administrator)")
    
    result := {
        "type": "sec_def_admin",
        "element": cond,
        "path": parent.path,
        "description": "Conditional privilege check - CWE-250: Execution with Unnecessary Privileges"
    }
}