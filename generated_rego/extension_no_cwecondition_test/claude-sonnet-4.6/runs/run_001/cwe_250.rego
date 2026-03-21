package glitch

import data.glitch_lib

root_user_attr_names := {"user", "remote_user", "become_user", "runAsUser", "run_as_user"}

privileged_attr_names := {"privileged", "run_as_root", "runAsRoot", "allowPrivilegeEscalation", "allow_privilege_escalation"}

command_attr_names := {"command", "cmd", "shell", "exec"}

is_root_value(value) {
    value.ir_type == "String"
    lower(value.value) == "root"
}

is_root_value(value) {
    value.ir_type == "Integer"
    value.value == 0
}

is_root_value(value) {
    value.ir_type == "String"
    value.value == "0"
}

attr_value_contains_root_ssh(attr) {
    walk(attr.value, [_, node])
    node.ir_type == "String"
    regex.match("(?i)root@", node.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == root_user_attr_names[_]
    is_root_value(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Component is configured to run as root user. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == privileged_attr_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Component is configured with elevated privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == command_attr_names[_]
    attr_value_contains_root_ssh(attr)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Command executes as root user via SSH. (CWE-250)"
    }
}