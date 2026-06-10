package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr_names := {"user", "run_as_user", "owner", "runas", "runAsUser", "uid"}
    attr.name == attr_names[_]

    attr.value.ir_type == "Integer"
    attr.value.value == 0

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Running as root user (UID 0) grants excessive permissions. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "privileged"

    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Privileged container execution grants excessive permissions. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "iam_policy"

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "actions"

    attr.value.ir_type == "Array"
    count(attr.value.value) == 1
    action := attr.value.value[0]
    action.ir_type == "String"
    action.value == "*"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Wildcard permissions in IAM policies grant excessive access. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "iam_policy"

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "resource"

    attr.value.ir_type == "String"
    attr.value.value == "*"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Wildcard resource in IAM policies grants excessive access. (CWE-250)"
    }
}