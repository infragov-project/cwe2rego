package glitch

import data.glitch_lib

user_attributes := {"user", "remote_user", "owner", "run_as_user", "sudo_user"}

high_privilege_users := {"root", "0", "Administrator", "admin", "wheel", "sudo"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name in user_attributes
    attr.value.ir_type == "String"
    attr.value.value in high_privilege_users

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Avoid running as root or other high-privilege users. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "bash"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name in user_attributes
    attr.value.ir_type == "String"
    attr.value.value in high_privilege_users

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Avoid running as root or other high-privilege users. (CWE-250)"
    }
}