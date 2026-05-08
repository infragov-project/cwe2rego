package glitch

import data.glitch_lib

# Detect root user in remote_user attribute (Ansible)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes at the parent level (playbook level)
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "remote_user"
    attr.value.ir_type == "String"
    regex.match("(?i)^root$", attr.value.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Playbook connecting as root user. (CWE-250)"
    }
}

# Detect root user in user attribute (Ansible tasks, Puppet exec, Chef execute)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "user"
    attr.value.ir_type == "String"
    regex.match("(?i)^root$", attr.value.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Task running with root user. (CWE-250)"
    }
}

# Detect SSH command executing as root (Puppet exec resource)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "command"
    
    # Use traverse to check for root@ pattern in the command value
    glitch_lib.traverse(attr.value, "root@")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Command executed via SSH as root. (CWE-250)"
    }
}