package glitch

import data.glitch_lib

# Set of administrative users that indicate unnecessary privileges
admin_users := {"root", "administrator", "admin", "Administrator", "Admin"}

# Set of attribute names that indicate user context
user_attributes := {"user", "remote_user", "run_as_user", "owner", "username", "become_user"}

# Set of attribute names that indicate command execution
command_attributes := {"command", "shell", "script"}

# Pattern 1: Detect user attributes with administrative users in unit blocks
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    user_attributes[attr.name]
    attr.value.ir_type == "String"
    admin_users[attr.value.value]
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - The resource is configured to run as an administrative user. (CWE-250)"
    }
}

# Pattern 1: Detect user attributes with administrative users in atomic units
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    user_attributes[attr.name]
    attr.value.ir_type == "String"
    admin_users[attr.value.value]
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - The resource is configured to run as an administrative user. (CWE-250)"
    }
}

# Pattern 2: Detect command attributes with administrative execution (e.g., root@) in unit blocks
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    command_attributes[attr.name]
    glitch_lib.traverse(attr.value, "root@")
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Administrative command execution - The command is executed as root, which may be unnecessary. (CWE-250)"
    }
}

# Pattern 2: Detect command attributes with administrative execution (e.g., root@) in atomic units
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    command_attributes[attr.name]
    glitch_lib.traverse(attr.value, "root@")
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Administrative command execution - The command is executed as root, which may be unnecessary. (CWE-250)"
    }
}