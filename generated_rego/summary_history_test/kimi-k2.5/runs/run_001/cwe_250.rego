package glitch

import data.glitch_lib

superuser_values := {"root", "administrator", "admin", "system", "superuser"}

user_indicators := {"remote_user", "user", "run_as", "run_as_user", "execution_user", "become_user", "owner", "container_user"}

command_indicators := {"command", "shell", "cmd", "execute", "command_line", "exec"}

attribute_indicators := {"unless", "onlyif", "creates", "path", "cwd", "environment"}

contains_any(str, patterns) {
    some p
    patterns[p]
    regex.match(sprintf("(?i).*%s.*", [p]), str)
}

is_user_attribute(attr) {
    attr.name == user_indicators[_]
}

is_superuser_value(val) {
    val.ir_type == "String"
    contains(lower(val.value), superuser_values[_])
}

# Walk through any node structure to find superuser patterns
walk_for_superuser(node) {
    walk(node, [_, n])
    is_superuser_value(n)
}

# Check if value contains superuser in string content itself
value_contains_superuser(val) {
    val.ir_type == "String"
    is_superuser_value(val)
}

is_privileged_true(attr) {
    attr.name == "privileged"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
} else {
    attr.name == "privileged"
    attr.value.ir_type == "String"
    lower(attr.value.value) == "true"
}

is_host_namespace(attr) {
    ns := {"host_network", "host_pid", "host_ipc", "host_users"}
    attr.name == ns[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
}

has_dangerous_capabilities(attr) {
    attr.value.ir_type == "Array"
    val := attr.value.value[_]
    val.ir_type == "String"
    contains(upper(val.value), "ALL")
} else {
    attr.value.ir_type == "String"
    regex.match("(?i)(all|sys_admin|net_admin)", attr.value.value)
}

is_security_disabled(attr) {
    attr.name == {"allow_privilege_escalation", "run_as_non_root"}[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
}

# Check if attribute is a command-related attribute that should be scanned for superuser patterns
is_command_attribute(attr) {
    attr.name == command_indicators[_]
} else {
    attr.name == attribute_indicators[_]
}

# Detection: direct superuser in user attribute - atomic units
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_user_attribute(attr)
    is_superuser_value(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Process or resource configured to run with superuser/root privileges. (CWE-250)"
    }
}

# Detection: superuser deep in value structures - atomic units
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_user_attribute(attr)
    walk_for_superuser(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Process or resource configured to run with superuser/root privileges. (CWE-250)"
    }
}

# Detection: command strings with superuser patterns (ssh root@, sudo, etc.)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    is_command_attribute(attr)
    walk_for_superuser(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Command contains superuser execution pattern. (CWE-250)"
    }
}

# Detection: superuser in unit block attributes - direct
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    count(parent.attributes) > 0
    
    attr := parent.attributes[_]
    is_user_attribute(attr)
    is_superuser_value(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Process or resource configured to run with superuser/root privileges. (CWE-250)"
    }
}

# Detection: superuser in unit block attributes - nested
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    count(parent.attributes) > 0
    
    attr := parent.attributes[_]
    is_user_attribute(attr)
    walk_for_superuser(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Process or resource configured to run with superuser/root privileges. (CWE-250)"
    }
}

# Detection: command with superuser in unit blocks
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    count(parent.attributes) > 0
    
    attr := parent.attributes[_]
    is_command_attribute(attr)
    walk_for_superuser(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Command contains superuser execution pattern. (CWE-250)"
    }
}

# Detection: privileged mode
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_privileged_true(attr)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Privileged mode enabled, granting excessive container privileges. (CWE-250)"
    }
}

# Detection: privileged mode in unit block
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    count(parent.attributes) > 0
    
    attr := parent.attributes[_]
    is_privileged_true(attr)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Privileged mode enabled, granting excessive container privileges. (CWE-250)"
    }
}

# Detection: host namespace sharing
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_host_namespace(attr)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Host namespace sharing enabled, increasing privilege risk. (CWE-250)"
    }
}

# Detection: dangerous capabilities
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    cap_indicators := {"capabilities", "add_capabilities", "drop_capabilities", "cap_add", "cap_drop"}
    attr.name == cap_indicators[_]
    has_dangerous_capabilities(attr)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Dangerous capabilities configured. (CWE-250)"
    }
}

# Detection: security disabled
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_security_disabled(attr)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Security restriction disabled, allowing privilege escalation. (CWE-250)"
    }
}

# Detection: any attribute containing superuser in deep structure
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name != ""
    not is_user_attribute(attr)
    not is_command_attribute(attr)
    walk_for_superuser(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Superuser reference found in configuration. (CWE-250)"
    }
}

# Detection: any attribute in unit blocks containing superuser
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    count(parent.attributes) > 0
    
    attr := parent.attributes[_]
    attr.name != ""
    not is_user_attribute(attr)
    not is_command_attribute(attr)
    walk_for_superuser(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Superuser reference found in configuration. (CWE-250)"
    }
}