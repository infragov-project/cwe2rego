package glitch

import data.glitch_lib

root_pattern := "^(root|0|administrator|admin)$"

is_root_user(value) {
    value.ir_type == "String"
    regex.match(root_pattern, value.value)
} else {
    value.ir_type == "Integer"
    value.value == 0
}

contains_root_execution(value) {
    glitch_lib.traverse(value, "root@")
} else {
    glitch_lib.traverse(value, "\\bsudo\\b")
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    user_attrs := {"user", "remote_user", "become_user"}
    attr.name == user_attrs[_]
    is_root_user(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Running as root user - This may lead to unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    user_attrs := {"user", "remote_user", "become_user"}
    attr.name == user_attrs[_]
    is_root_user(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Running as root user - This may lead to unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    command_attrs := {"command", "cmd", "shell", "script"}
    attr.name == command_attrs[_]
    contains_root_execution(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Command execution with root privileges - This may lead to unnecessary privileges. (CWE-250)"
    }
}