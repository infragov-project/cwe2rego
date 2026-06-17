package glitch

import data.glitch_lib

privileged_names := {"privileged", "privileged_mode"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == privileged_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Privileged container mode enabled (CWE-250)"
    }
}

root_user_attr_names := {"user", "run_as_user", "become_user", "group", "remote_user"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == root_user_attr_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^root$", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Process running as root user (CWE-250)"
    }
}

uid_zero_names := {"runAsUser", "run_as_user", "user", "run_as_group", "runAsGroup"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == uid_zero_names[_]
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Running with UID/GID 0 (root) (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "runAsNonRoot"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - runAsNonRoot is set to false (CWE-250)"
    }
}

priv_esc_names := {"allowPrivilegeEscalation", "allow_privilege_escalation"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == priv_esc_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Privilege escalation is permitted (CWE-250)"
    }
}

no_new_priv_names := {"no_new_privileges", "NoNewPrivileges"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == no_new_priv_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - No new privileges protection is disabled (CWE-250)"
    }
}

host_ns_names := {"hostPID", "hostIPC", "hostNetwork", "host_pid"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == host_ns_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Host namespace sharing enabled (CWE-250)"
    }
}

host_mode_names := {"network_mode", "pid_mode", "ipc_mode"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == host_mode_names[_]
    attr.value.ir_type == "String"
    attr.value.value == "host"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Container using host network/pid/ipc mode (CWE-250)"
    }
}

dangerous_caps := {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE", "SETUID", "SETGID"}
cap_add_names := {"cap_add", "capabilities"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cap_add_names[_]
    glitch_lib.traverse(attr.value, dangerous_caps)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Dangerous Linux capabilities granted (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == cap_add_names[_]
    glitch_lib.traverse(attr.value, "^ALL$")
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - All Linux capabilities granted (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "automountServiceAccountToken"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Service account token auto-mounted (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "hostPath"
    attr.value.ir_type == "String"
    regex.match("^(/|/etc(/.*)?|/proc(/.*)?|/sys(/.*)?|/var/run/docker\\.sock)$", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Sensitive host path mounted (CWE-250)"
    }
}

iam_action_names := {"Action", "actions"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == iam_action_names[_]
    glitch_lib.traverse(attr.value, "^\\*$")
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Wildcard IAM action grants unrestricted access (CWE-250)"
    }
}

rbac_wildcard_names := {"verbs", "resources"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == rbac_wildcard_names[_]
    glitch_lib.traverse(attr.value, "^\\*$")
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Wildcard RBAC permissions granted (CWE-250)"
    }
}

admin_role_names := {"role", "clusterRole"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == admin_role_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(^admin$|cluster-admin)", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Admin or cluster-admin role binding (CWE-250)"
    }
}

svc_cred_names := {"username", "db_user", "master_username"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == svc_cred_names[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(root|admin|sa)$", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Admin or root credentials used for service account (CWE-250)"
    }
}

setid_names := {"setuid", "setgid"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == setid_names[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Setuid/setgid bit enabled on file (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "policy_arn"
    attr.value.ir_type == "String"
    regex.match("(?i)(AdministratorAccess|PowerUserAccess|FullAccess)", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Overly permissive IAM policy attached (CWE-250)"
    }
}

command_attr_names := {"command", "cmd", "shell"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == command_attr_names[_]
    glitch_lib.traverse(attr.value, "(?i).*root@.*")
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Command executes as root via remote connection (CWE-250)"
    }
}