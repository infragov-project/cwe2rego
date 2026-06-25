package glitch

import data.glitch_lib

privileged_true_attrs := {
    "privileged", "allow_privilege_escalation", "allowPrivilegeEscalation",
    "run_as_root", "runAsRoot", "enable_privileged", "privileged_mode",
    "hostPID", "hostIPC", "hostNetwork", "host_pid", "host_network",
    "automountServiceAccountToken"
}

dangerous_capabilities := {
    "ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE",
    "DAC_OVERRIDE", "SETUID", "SETGID", "SYS_MODULE"
}

user_attrs := {
    "user", "db_user", "remote_user", "run_as", "become_user"
}

collect_strings(node) = strs {
    strs := {s |
        walk(node, [_, n])
        n.ir_type == "String"
        s := n.value
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == privileged_true_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Privileged execution mode enabled. (CWE-250)"
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
        "description": "Execution with Unnecessary Privileges - Non-root execution not enforced (runAsNonRoot: false). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"run_as_user", "runAsUser"}[_]
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Container running as root user (UID 0). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == user_attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(root|admin|sa)$", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Service configured to run as privileged user. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"network_mode", "ipc_mode"}[_]
    attr.value.ir_type == "String"
    attr.value.value == "host"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Host namespace sharing via network or IPC mode. (CWE-250)"
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
    cap.value == dangerous_capabilities[_]
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Excessive Linux kernel capabilities added. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"resources", "verbs", "Action", "actions"}[_]
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    elem.value == "*"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Wildcard permissions grant excessive access. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"Action", "Resource", "actions", "resources"}[_]
    attr.value.ir_type == "String"
    attr.value.value == "*"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Wildcard permissions grant excessive access. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"hostPath", "host_path"}[_]
    attr.value.ir_type == "String"
    regex.match("^(/|/etc|/var/run|/proc|/sys)(/.*)?$", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Sensitive host path mounted in container. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"superuser", "grant_all_privileges"}[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Database superuser or full privileges granted. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"role", "policy", "roleRef"}[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(cluster-admin|administratoraccess|fullaccess|poweruser)", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Administrative role or policy assigned. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"cidr", "cidr_block", "cidr_ip"}[_]
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0/0"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Unrestricted network access rule (0.0.0.0/0). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"command", "cmd", "exec", "run", "entrypoint", "script"}[_]
    strs := collect_strings(attr.value)
    s := strs[_]
    regex.match("(?i)(root@|\\bsudo\\s|USER\\s+root)", s)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Command executed as privileged user. (CWE-250)"
    }
}