package glitch

import data.glitch_lib

privileged_user_values := {"root", "admin", "administrator", "0"}
privileged_group_values := {"root", "admin", "administrators", "0"}
privilege_escalation_keywords := {"sudo", "su", "sudoers", "privileged", "elevated", "admin_rights", "admin_privileges", "run_as_root", "run_as_admin"}
user_attributes := {"user", "username", "remote_user", "owner", "runas", "exec_user"}
group_attributes := {"group", "groupname", "exec_group"}

check_privileged_user(value) {
    value.ir_type == "String"
    reg := privileged_user_values[_]
    lower(value.value) == reg
} else {
    value.ir_type == "Integer"
    value.value == 0
}

check_privileged_group(value) {
    value.ir_type == "String"
    reg := privileged_group_values[_]
    lower(value.value) == reg
} else {
    value.ir_type == "Integer"
    value.value == 0
}

check_privilege_escalation(value) {
    value.ir_type == "String"
    reg := privilege_escalation_keywords[_]
    contains(lower(value.value), reg)
}

contains(str, substr) {
    regex.match(sprintf(".*%s.*", [substr]), str)
}

has_root_ssh_reference(value) {
    walk(value, [_, node])
    node.ir_type == "String"
    contains(node.value, "root@")
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == user_attributes[_]
    check_privileged_user(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - The component executes with a privileged user account that may be higher than required. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == group_attributes[_]
    check_privileged_group(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - The component executes with a privileged group that may be higher than required. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "become"
    check_privilege_escalation(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - The component is configured with unnecessary privilege escalation mechanisms. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    parent.type == "tasks"
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.name.ir_type == "String"
    lower(node.name.value) == "become"
    result := {
        "type": "sec_def_admin",
        "element": node,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - The task uses privilege escalation which may be unnecessary. Review if lower privileges can be used. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "command"
    has_root_ssh_reference(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - The command uses privileged user in SSH or execution context which may be unnecessary. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == user_attributes[_]
    check_privileged_user(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - The block executes with a privileged user account that may be higher than required. (CWE-250)"
    }
}