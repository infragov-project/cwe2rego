package glitch

import data.glitch_lib

dangerous_caps := {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE", "SYS_RAWIO", "SYS_BOOT"}

sensitive_host_paths := {"/var/run/docker.sock", "/proc", "/sys", "/dev", "/etc", "/root", "/run/containerd"}

admin_policy_names := {"AdministratorAccess", "PowerUserAccess", "cluster-admin"}

is_wildcard_value(value) {
    value.ir_type == "String"
    value.value == "*"
}

is_wildcard_value(value) {
    value.ir_type == "Array"
    elem := value.value[_]
    elem.ir_type == "String"
    elem.value == "*"
}

is_sensitive_iam_action(value) {
    value.ir_type == "String"
    regex.match("(?i)^(iam:\\*|iam:PassRole|iam:CreatePolicyVersion|sts:AssumeRole|s3:\\*|ec2:\\*)$", value.value)
}

is_sensitive_iam_action(value) {
    value.ir_type == "Array"
    elem := value.value[_]
    elem.ir_type == "String"
    regex.match("(?i)^(iam:\\*|iam:PassRole|iam:CreatePolicyVersion|sts:AssumeRole|s3:\\*|ec2:\\*)$", elem.value)
}

has_security_context(node) {
    walk(node, [_, child])
    child.ir_type == "Attribute"
    lower(child.name) == "securitycontext"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "privileged"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged container mode enabled - grants full host-level kernel capabilities. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "runasuser"
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container configured to run as root user (UID 0). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "runasgroup"
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container configured to run in root group (GID 0). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"user", "run_as", "account", "service_account", "worker_user", "daemon_user", "become_user"}[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^(root|0|system|localsystem|administrator|nt authority\\\\system)(:[^\\s]*)?$", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Service or container running as a high-privilege OS account (root, SYSTEM, Administrator). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "allowprivilegeescalation"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privilege escalation permitted - allowPrivilegeEscalation set to true. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "runasnonroot"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "runAsNonRoot explicitly set to false - container may run as root. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"cap_add", "add", "capadd", "linux_cap"}[_]
    glitch_lib.traverse(attr.value, dangerous_caps)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive or dangerous Linux capability added (e.g., ALL, SYS_ADMIN, NET_ADMIN). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"hostpid", "hostipc", "hostnetwork"}[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Host namespace sharing enabled (hostPID/hostIPC/hostNetwork: true). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"network_mode", "pid", "ipc"}[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == "host"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container configured to share host namespace (network_mode/pid/ipc: host). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "readonlyrootfilesystem"
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Root filesystem is writable - readOnlyRootFilesystem set to false. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"volumes", "binds", "mounts"}[_]
    glitch_lib.traverse(attr.value, sensitive_host_paths)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Sensitive host path mounted into container (e.g., /proc, /dev, /var/run/docker.sock). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hp_attr])
    hp_attr.ir_type == "Attribute"
    lower(hp_attr.name) == "hostpath"
    walk(hp_attr, [_, path_attr])
    path_attr.ir_type == "Attribute"
    lower(path_attr.name) == "path"
    path_attr.value.ir_type == "String"
    glitch_lib.traverse(path_attr.value, sensitive_host_paths)
    result := {
        "type": "sec_def_admin",
        "element": path_attr,
        "path": parent.path,
        "description": "Sensitive host path mounted via Kubernetes hostPath volume (e.g., /proc, /dev, /var/run/docker.sock). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"action", "actions"}[_]
    is_wildcard_value(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard IAM action (*) grants all permissions to any service. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"verbs", "resources", "apigroups"}[_]
    is_wildcard_value(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard RBAC permission (*) grants unrestricted access to Kubernetes API resources. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"managed_policy_arns", "policy_arn", "policies", "policy", "attached_policy_arns"}[_]
    glitch_lib.traverse(attr.value, admin_policy_names)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Administrative IAM/RBAC policy attached (AdministratorAccess, PowerUserAccess, cluster-admin). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"action", "actions"}[_]
    is_sensitive_iam_action(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Sensitive IAM action assigned that may enable privilege escalation (iam:PassRole, sts:AssumeRole, service wildcards). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "automountserviceaccounttoken"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Service account token automatically mounted - may expose Kubernetes API credentials unnecessarily. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "mode"
    attr.value.ir_type == "String"
    regex.match("(?i)^(0?(4[0-9]{3}|6[0-9]{3})|.*\\+s.*|.*setuid.*|.*setgid.*)$", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "SUID/SGID bit set on file - enables execution with owner/group-level privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "mode"
    attr.value.ir_type == "Integer"
    attr.value.value == {4755, 6755, 2541, 3565}[_]
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "SUID/SGID bit set on file (octal 4755/6755) - enables execution with elevated privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"command", "cmd", "inline", "script"}[_]
    attr.value.ir_type == "String"
    regex.match("(?i).*chmod\\s+.*([46][0-9]{3}|\\+s).*", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "chmod command setting SUID/SGID bit - enables execution with owner/group-level privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    lower(node.type) == {"container", "pod", "service", "deployment", "statefulset", "daemonset"}[_]
    not has_security_context(node)
    result := {
        "type": "sec_def_admin",
        "element": node,
        "path": parent.path,
        "description": "Container or pod definition missing security context - defaults to permissive runtime behavior. (CWE-250)"
    }
}