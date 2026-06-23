package glitch

import data.glitch_lib

admin_keywords := {"admin", "administrator", "root", "superuser", "owner", "full_access", "full", "privileged", "system"}

wildcard_patterns := {"*", "all", "any", "unrestricted", "global", "account_wide", "organization_wide", "cross_account"}

write_permissions := {"write", "read_write", "modify", "put", "post", "update", "delete", "manage", "control"}

privileged_capabilities := {"privileged", "host_network", "host_pid", "host_ipc", "all_capabilities", "NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "DAC_READ_SEARCH"}

execution_user_attrs := {"remote_user", "user", "become_user", "run_as", "owner", "group", "run_as_user", "runas", "runuser", "su_user"}

admin_role_attrs := {"role", "policy", "assume_role", "iam_role"}

permission_attrs := {"permissions", "actions", "resources", "effect"}

# Check if value contains any of the keyword patterns (case insensitive substring match)
contains_keyword(value, keywords) {
    value.ir_type == "String"
    keyword := keywords[_]
    regex.match(sprintf("(?i).*%s.*", [keyword]), value.value)
}

# Check for wildcard permissions
is_wildcard_permission(value) {
    value.ir_type == "String"
    value.value == "*"
} else {
    value.ir_type == "String"
    value.value == "*:*"
} else {
    value.ir_type == "String"
    regex.match(`^\*+[:\/]*\**$`, value.value)
}

# Case insensitive contains check
contains_insensitive(str, substr) {
    regex.match(sprintf("(?i).*%s.*", [substr]), str)
}

# Check if any string in a Sum operation contains admin keyword
has_admin_in_sum(sum_node, keywords) {
    sum_node.ir_type == "Sum"
    walk(sum_node, [_, n])
    n.ir_type == "String"
    keyword := keywords[_]
    contains_insensitive(n.value, keyword)
}

# Check for privileged security context
is_privileged_context(attr) {
    attr.name == "privileged"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
}

is_privileged_context(attr) {
    attr.name == "allow_privilege_escalation"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
}

is_privileged_context(attr) {
    attr.name == "run_as_non_root"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
}

is_privileged_context(attr) {
    attr.name == "read_only_root_filesystem"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
}

# Check for admin/trust policy with wildcard principal
is_overly_permissive_trust(attr) {
    attr.name == "trust_policy"
    glitch_lib.traverse(attr.value, "*")
}

# Check for broad network access from privileged context
is_broad_network_access(attr) {
    attr.name == "ingress"
    attr.value.ir_type == "String"
    contains_insensitive(attr.value.value, "0.0.0.0/0")
}

# Check if attribute represents execution with admin user
is_admin_execution(attr) {
    attr.name == execution_user_attrs[_]
    contains_keyword(attr.value, admin_keywords)
}

# Check for admin in role/policy attributes
is_admin_role(attr) {
    attr.name == admin_role_attrs[_]
    contains_keyword(attr.value, admin_keywords)
}

# Check for wildcard in permission-related attributes
is_wildcard_permission_attr(attr) {
    attr.name == permission_attrs[_]
    is_wildcard_permission(attr.value)
}

# Check for write permissions without read-only restriction
is_excessive_write_permission(attr) {
    attr.name == "permissions"
    contains_keyword(attr.value, write_permissions)
    not contains_insensitive(attr.value.value, "read")
}

# Check nested structures for privileged capabilities
has_privileged_nested(attr) {
    attr.value.ir_type == "Hash"
    glitch_lib.traverse(attr.value, privileged_capabilities[_])
}

has_privileged_nested(attr) {
    attr.value.ir_type == "Array"
    glitch_lib.traverse(attr.value, privileged_capabilities[_])
}

has_privileged_nested(attr) {
    attr.value.ir_type == "BlockExpr"
    glitch_lib.traverse(attr.value, privileged_capabilities[_])
}

# Get attributes from UnitBlock directly
unit_block_attrs(block) = attrs {
    attrs = {attr |
        attr := block.attributes[_]
    }
}

# Get attributes from nested unit blocks
nested_unit_block_attrs(parent) = attrs {
    attrs = {attr |
        nested := parent.unit_blocks[_]
        attr := nested.attributes[_]
    }
}

# Glitch_Analysis for admin execution in atomic units
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_admin_execution(attr)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Resource configured to run with elevated user privileges. (CWE-250)"
    }
}

# Glitch_Analysis for admin execution in unit block attributes (Ansible playbook-level)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := parent.attributes[_]
    is_admin_execution(attr)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Resource configured to run with elevated user privileges. (CWE-250)"
    }
}

# Glitch_Analysis for admin execution in nested unit blocks
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    nested := parent.unit_blocks[_]
    attr := nested.attributes[_]
    is_admin_execution(attr)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Resource configured to run with elevated user privileges. (CWE-250)"
    }
}

# Glitch_Analysis for admin in command strings (Puppet exec with root@)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Sum"
    has_admin_in_sum(attr.value, admin_keywords)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Command contains hardcoded administrative user reference. (CWE-250)"
    }
}

# Glitch_Analysis for admin roles
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_admin_role(attr)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Resource configured with excessive administrative role. (CWE-250)"
    }
}

# Glitch_Analysis for wildcard permissions
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_wildcard_permission_attr(attr)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Policy contains wildcard permissions granting excessive access. (CWE-250)"
    }
}

# Glitch_Analysis for privileged security context
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_privileged_context(attr)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Resource configured with privileged execution context. (CWE-250)"
    }
}

# Glitch_Analysis for overly permissive trust
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_overly_permissive_trust(attr)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Trust policy allows overly broad principal assumption. (CWE-250)"
    }
}

# Glitch_Analysis for excessive write permissions
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_excessive_write_permission(attr)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Write permissions assigned potentially exceeding operational needs. (CWE-250)"
    }
}

# Glitch_Analysis for nested privileged configurations
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    has_privileged_nested(attr)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Nested configuration contains privileged security settings. (CWE-250)"
    }
}