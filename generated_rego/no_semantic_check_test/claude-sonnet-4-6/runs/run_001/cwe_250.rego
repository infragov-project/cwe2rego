package glitch

import data.glitch_lib

privileged_true_attrs := {
    "privileged", "allowprivilegeescalation", "hostpid", "hostnetwork",
    "hostipc", "privileged_mode", "root_access", "publicly_accessible", "public_access"
}

false_protection_attrs := {
    "runasnonroot", "readonlyrootfilesystem", "block_public_acls", "block_public_policy"
}

root_user_attrs := {"user", "run_as_user", "runasuser", "db_user", "master_username"}

dangerous_capabilities := {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO"}

overprivileged_policy_values := {"*", "AdministratorAccess", "FullAccess", "PowerUser"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == privileged_true_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Privileged or elevated access flag is enabled. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == false_protection_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Security protection flag is disabled. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^runasuser$|^run_as_user$|^runasgroup$|^run_as_group$", attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value == 0

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Container configured to run as root (UID/GID 0). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == root_user_attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^root$|^admin$", attr.value.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Service configured to run as root or admin user. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^cap_add$|^add$", attr.name)
    glitch_lib.traverse(attr.value, dangerous_capabilities)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Dangerous Linux capabilities added to container. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^actions?$|^resources?$|^managed_policy_arns?$|^policy_arn$", attr.name)
    glitch_lib.traverse(attr.value, overprivileged_policy_values)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Wildcard or overly permissive IAM policy. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^principals?$", attr.name)
    attr.value.ir_type == "String"
    attr.value.value == "*"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Wildcard principal grants access to any identity. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "acl"
    attr.value.ir_type == "String"
    regex.match("(?i)public", attr.value.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Storage resource configured with public ACL. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)NOPASSWD.*ALL|sudo\\s+-i|sudo\\s+su\\b|chmod\\s+777", attr.value.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Unrestricted sudo or overly permissive provisioning in script. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^role_?ref$|^role_?name$|^rolename$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)cluster-admin|^admin$", attr.value.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Service account bound to admin or cluster-admin role. (CWE-250)"
    }
}