package glitch

import data.glitch_lib

privileged_user_attributes := {"remote_user", "user", "run_as", "become_user", "owner", "group"}
privileged_users := {"root", "administrator", "admin", "wheel", "sudo", "superuser", "system"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check UnitBlock attributes (like Ansible playbooks)
    unit_attrs := glitch_lib.all_attributes(parent)
    unit_attr := unit_attrs[_]
    unit_attr.name in privileged_user_attributes
    unit_attr.value.ir_type == "String"
    unit_attr.value.value in privileged_users
    
    result := {
        "type": "sec_def_admin",
        "element": unit_attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - The script is configured to run as a privileged user (root) which is unnecessary and increases security risk. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check AtomicUnit attributes (like Chef resources, Ansible tasks)
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in privileged_user_attributes
    attr.value.ir_type == "String"
    attr.value.value in privileged_users
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - The script is configured to run as a privileged user (root) which is unnecessary and increases security risk. (CWE-250)"
    }
}