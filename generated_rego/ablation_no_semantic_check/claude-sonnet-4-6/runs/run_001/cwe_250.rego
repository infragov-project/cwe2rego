package glitch

import data.glitch_lib

check_permissive_mode(value) {
    value.ir_type == "String"
    regex.match("^0?(?:777|666)$", value.value)
}

check_permissive_mode(value) {
    value.ir_type == "Integer"
    value.value == 777
}

check_permissive_mode(value) {
    value.ir_type == "Integer"
    value.value == 666
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(privileged|allowprivilegeescalation|hostpid|hostipc|hostnetwork|shareprocessnamespace|automountserviceaccounttoken)$", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - privileged or elevated host access enabled. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^runasuser$", attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value == 0

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - container configured to run as root (runAsUser: 0). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^runasnonroot$", attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - runAsNonRoot explicitly set to false. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(actions|verbs|resources|apigroups)$", attr.name)
    glitch_lib.traverse(attr.value, "^\\*$")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - wildcard permissions granted. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(policy_arn|policy|managed_policy_arns|role_arn|role)$", attr.name)
    glitch_lib.traverse(attr.value, "(?i)(administratoraccess|fullacc|poweruser|cluster.?admin|roles/owner|roles/editor|roles/contributor)")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - admin-level policy or role assigned. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^add$", attr.name)
    glitch_lib.traverse(attr.value, {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO"})

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - dangerous Linux capabilities added. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(hostpath|path)$", attr.name)
    glitch_lib.traverse(attr.value, "(?i)^(/|/etc|/proc|/sys|/root|/var/run/docker\\.sock)")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - sensitive host path mounted. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(become_user|run_as|execute_as)$", attr.name)
    glitch_lib.traverse(attr.value, "(?i)^(root|administrator|admin)$")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - automation task configured to run as privileged user. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(username|master_username|db_user|database_user)$", attr.name)
    glitch_lib.traverse(attr.value, "(?i)^(root|admin|sa|superuser|postgres|administrator)$")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - admin-level database credentials configured. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(mode|file_permission|directory_permission|defaultmode)$", attr.name)
    check_permissive_mode(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - world-writable file or volume permissions configured. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(scopes|scope)$", attr.name)
    glitch_lib.traverse(attr.value, "(?i)(cloud.platform|cloud-platform|full.access|all)")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - compute identity assigned full-access scope. (CWE-250)"
    }
}