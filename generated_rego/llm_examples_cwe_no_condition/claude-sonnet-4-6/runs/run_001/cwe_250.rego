package glitch

import data.glitch_lib

privileged_true_attrs := {"privileged", "allow_privilege_escalation", "run_as_root"}

root_user_attrs := {"user", "run_as_user", "run_as", "become_user"}

is_true_value(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_true_value(value) {
    value.ir_type == "String"
    lower(value.value) == "true"
}

is_privileged_user(value) {
    value.ir_type == "String"
    lower(value.value) == "root"
}

is_privileged_user(value) {
    value.ir_type == "String"
    lower(value.value) == "administrator"
}

is_privileged_user(value) {
    value.ir_type == "Integer"
    value.value == 0
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == privileged_true_attrs[_]
    is_true_value(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - The configuration enables elevated privileges unnecessarily. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]

    attr.name == root_user_attrs[_]
    is_privileged_user(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - The configuration runs as a privileged user, violating least privilege principle. (CWE-250)"
    }
}