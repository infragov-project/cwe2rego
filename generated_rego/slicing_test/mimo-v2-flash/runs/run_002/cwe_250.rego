package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for direct attribute in UnitBlock (e.g., Ansible remote_user)
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "remote_user"
    attr.value.ir_type == "String"
    attr.value.value == "root"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Remote execution as root user detected. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    # Check for user attribute in atomic units (e.g., Chef bash, script resources)
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "user"
    attr.value.ir_type == "String"
    attr.value.value == "root"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Execution as root user detected. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for command attributes in atomic units that contain 'root@' (e.g., Puppet exec)
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "command"
    
    # Check if the command string contains 'root@' which indicates SSH execution as root
    glitch_lib.traverse(attr.value, "root@")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - SSH execution as root user detected. (CWE-250)"
    }
}