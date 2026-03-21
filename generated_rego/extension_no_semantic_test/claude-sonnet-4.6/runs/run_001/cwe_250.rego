package glitch

import data.glitch_lib

dangerous_caps := {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE", "SYS_MODULE", "CAP_SYS_RAWIO"}

bool_true_insecure_attrs := {
    "privileged", "privileged_mode", "enable_privileged", "insecure_privilege",
    "allowPrivilegeEscalation", "allow_privilege_escalation",
    "hostPID", "hostNetwork", "hostIPC", "shareProcessNamespace",
    "host_network", "host_pid", "host_ipc", "superuser"
}

bool_false_insecure_attrs := {"runAsNonRoot", "no_new_privileges"}

root_uid_attrs := {"runAsUser", "uid", "run_as_user"}

root_user_string_attrs := {"user", "runAsUser", "run_as_user", "db_user"}

wildcard_perm_attrs := {"verbs", "resources", "apiGroups", "actions", "Action", "Resource"}

sensitive_mount_paths := {"/etc", "/proc", "/sys", "/var/run/docker.sock"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == bool_true_insecure_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges: insecure security setting enabled. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == bool_false_insecure_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges: security control disabled. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == root_uid_attrs[_]
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Process configured to run as root user (uid=0). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == root_user_string_attrs[_]
    attr.value.ir_type == "String"
    attr.value.value == ["root", "0", "admin"][_]
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Process or service configured to run as root or admin user. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "add"
    attr.value.ir_type == "Array"
    cap := attr.value.value[_]
    cap.ir_type == "String"
    cap.value == dangerous_caps[_]
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive Linux capabilities granted to container. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == wildcard_perm_attrs[_]
    attr.value.ir_type == "Array"
    entry := attr.value.value[_]
    entry.ir_type == "String"
    entry.value == "*"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard permissions grant excessive access in RBAC or IAM policy. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == wildcard_perm_attrs[_]
    attr.value.ir_type == "String"
    attr.value.value == "*"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard permissions grant excessive access in RBAC or IAM policy. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i).*(cluster-admin|AdministratorAccess|ALL PRIVILEGES|GRANT ALL).*", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive admin role or excessive privilege assignment detected. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "mountPath"
    attr.value.ir_type == "String"
    startswith(attr.value.value, sensitive_mount_paths[_])
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Sensitive host path mounted in container, granting elevated access. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.name == "hostPath"
    result := {
        "type": "sec_def_admin",
        "element": node,
        "path": parent.path,
        "description": "hostPath volume exposes host filesystem to container. (CWE-250)"
    }
}