package glitch

import data.glitch_lib
import future.keywords.in

# Privilege elevation keywords in names
privilege_elevated_names := {"elevated", "privileged", "administrator", "admin", "root", "sudo", "runas", "impersonate", "setuid", "setgid"}

# Privilege escalation commands
privilege_escalation_cmds := {"sudo", "su", "runas", "impersonate", "setuid", "setgid"}

# Excessive permission indicators
excessive_permissions := {"*", "all", "full", "unrestricted", "wildcard"}

# Privileged execution context keywords
privileged_context := {"privileged", "elevation_required", "requires_privilege", "bypass_policy", "force", "ignore_restrictions", "persistent", "permanent", "always_on", "retain_privilege", "keep_session"}

# High privilege identity keywords
privileged_identity := {"root", "administrator", "admin", "system", "service_account"}

# Check if string matches any pattern in set
matches_any(str, patterns) {
    patterns[p]
    regex.match(sprintf("(?i)%s", [p]), str)
}

# Check for privileged execution in string value
has_privileged_execution(value) {
    value.ir_type == "String"
    matches_any(value.value, privilege_escalation_cmds)
}

# Check for excessive permission grant
has_excessive_permission(value) {
    value.ir_type == "String"
    matches_any(value.value, excessive_permissions)
}

# Check for privileged name in attribute or variable
has_privileged_name(name) {
    matches_any(name, privilege_elevated_names)
}

# Check for privileged boolean flag
is_privileged_flag(attr) {
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    matches_any(attr.name, privileged_context)
}

# Check for privileged context in string - identity check
has_privileged_identity(value) {
    value.ir_type == "String"
    matches_any(value.value, privileged_identity)
}

# Check for privileged context keywords in string
has_privileged_context_keyword(value) {
    value.ir_type == "String"
    matches_any(value.value, privileged_context)
}

# Walk-based traversal of complex values to find privilege patterns
complex_contains_privilege(value) {
    walk(value, [_, node])
    node.ir_type == "String"
    has_privileged_identity(node)
}

complex_contains_privilege(value) {
    walk(value, [_, node])
    node.ir_type == "String"
    has_privileged_context_keyword(node)
}

# Check if attribute indicates privilege escalation
is_privilege_escalation_attr(attr) {
    has_privileged_name(attr.name)
}

is_privilege_escalation_attr(attr) {
    has_privileged_execution(attr.value)
}

is_privilege_escalation_attr(attr) {
    has_excessive_permission(attr.value)
}

is_privilege_escalation_attr(attr) {
    is_privileged_flag(attr)
}

is_privilege_escalation_attr(attr) {
    complex_contains_privilege(attr.value)
}

# Check for privilege patterns in command strings
command_indicates_privilege(value) {
    value.ir_type == "String"
    pattern := `^(?i).*(\bsudo\b|\bsu\b|\brunas\b|\bsetuid\b|\bsetgid\b).*`
    regex.match(pattern, value.value)
}

# Check for hardcoded privileged account
has_hardcoded_privileged_account(value) {
    value.ir_type == "String"
    lower_val := lower(value.value)
    privileged_accounts := ["root", "administrator", "admin", "system"]
    account := privileged_accounts[_]
    lower_val == account
}

# Get all attributes from a unit block including nested blocks
all_unit_block_attributes(ub) = attrs {
    attrs = {attr |
        # Direct attributes on the unit block
        walk(ub, [_, attr])
        attr.ir_type == "Attribute"
        attr.value.ir_type != "BlockExpr"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_privilege_escalation_attr(attr)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - The component is configured with elevated or excessive privileges that may not be required. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    node.name.ir_type == "String"
    has_privileged_name(node.name.value)
    
    result := {
        "type": "sec_def_admin",
        "element": node,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Resource name indicates privileged execution context. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    command_indicates_privilege(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Command string contains privilege escalation mechanism. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    has_hardcoded_privileged_account(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Hardcoded privileged account detected. (CWE-250)"
    }
}

# Check unit block attributes (for Ansible playbook-level attributes like remote_user)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check direct attributes on unit blocks
    attr := parent.attributes[_]
    attr.ir_type == "Attribute"
    
    # Check for privileged identity in value
    has_privileged_identity(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Hardcoded privileged account detected in configuration. (CWE-250)"
    }
}

# Check nested unit block attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check nested unit blocks (for Ansible plays)
    nested := parent.unit_blocks[_]
    attr := nested.attributes[_]
    attr.ir_type == "Attribute"
    
    # Check for privileged identity in value
    has_privileged_identity(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Hardcoded privileged account detected in configuration. (CWE-250)"
    }
}

# Check for privilege escalation attributes by name on unit blocks
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attr := parent.attributes[_]
    attr.ir_type == "Attribute"
    has_privileged_name(attr.name)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Configuration uses elevated privilege settings. (CWE-250)"
    }
}

# Check for privilege escalation attributes by name on nested unit blocks
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    nested := parent.unit_blocks[_]
    attr := nested.attributes[_]
    attr.ir_type == "Attribute"
    has_privileged_name(attr.name)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Configuration uses elevated privilege settings. (CWE-250)"
    }
}

# Check variables for privileged accounts
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    
    has_privileged_identity(var.value)
    
    result := {
        "type": "sec_def_admin",
        "element": var,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Variable contains hardcoded privileged account. (CWE-250)"
    }
}

# Check nested unit block variables
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    nested := parent.unit_blocks[_]
    var := nested.variables[_]
    
    has_privileged_identity(var.value)
    
    result := {
        "type": "sec_def_admin",
        "element": var,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Variable contains hardcoded privileged account. (CWE-250)"
    }
}