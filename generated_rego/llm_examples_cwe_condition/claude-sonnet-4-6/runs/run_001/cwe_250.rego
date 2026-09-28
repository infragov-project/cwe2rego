package glitch

import data.glitch_lib

priv_true_names := {"privileged", "allowPrivilegeEscalation", "hostPID", "hostIPC", "hostNetwork", "automountServiceAccountToken"}

dangerous_caps := {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_RAW", "DAC_READ_SEARCH", "SYS_RAWIO"}

wildcard_perm_names := {"action", "Action", "resource", "Resource", "verbs", "apiGroups", "resources", "notAction", "NotAction", "notResource", "NotResource"}

overprivileged_pattern := "(?i)(AdministratorAccess|PowerUser|FullAccess)"

overprivileged_exact_pattern := "(?i)^(AdministratorAccess|PowerUser|FullAccess|cluster-admin|clusterAdmin|roles/owner|roles/editor)$"

role_ref_keys := {"role", "roleName", "clusterRole", "clusterRoleName", "roleRef", "policyArn", "managedPolicyArn", "policy", "roleArn"}

is_bool_true(v) {
    v.ir_type == "Boolean"
    v.value == true
}

is_bool_true(v) {
    v.ir_type == "VariableReference"
    v.value == "true"
}

is_bool_true(v) {
    v.ir_type == "String"
    lower(v.value) == "true"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == priv_true_names[_]
    is_bool_true(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Privilege-granting flag set to true. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    entry.key.value == priv_true_names[_]
    is_bool_true(entry.value)
    result := {
        "type": "sec_def_admin",
        "element": entry.key,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Privilege-granting flag set to true. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    entry.key.value == "runAsNonRoot"
    entry.value.ir_type == "Boolean"
    entry.value.value == false
    result := {
        "type": "sec_def_admin",
        "element": entry.key,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - runAsNonRoot set to false allows root execution. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"uid", "runAsUser", "user_id"}[_]
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - User UID set to root (0). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    entry.key.value == {"runAsUser", "uid", "user_id"}[_]
    entry.value.ir_type == "Integer"
    entry.value.value == 0
    result := {
        "type": "sec_def_admin",
        "element": entry.key,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - User UID set to root (0). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"user", "username"}[_]
    attr.value.ir_type == "String"
    regex.match("^(root|0)$", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - User identity set to root. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "mode"
    attr.value.ir_type == "String"
    regex.match("^0?777$", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - World-writable file mode set. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"add", "cap_add"}[_]
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    elem.value == dangerous_caps[_]
    result := {
        "type": "sec_def_admin",
        "element": elem,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Dangerous Linux capability added. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    entry.key.value == {"add", "cap_add"}[_]
    entry.value.ir_type == "Array"
    elem := entry.value.value[_]
    elem.ir_type == "String"
    elem.value == dangerous_caps[_]
    result := {
        "type": "sec_def_admin",
        "element": elem,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Dangerous Linux capability added. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    regex.match("(?i)--cap-add=(ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|NET_RAW|DAC_READ_SEARCH|SYS_RAWIO)", elem.value)
    result := {
        "type": "sec_def_admin",
        "element": elem,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Dangerous Linux capability added via CLI flag. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    regex.match("(?i)--(net|pid|ipc|uts)=host", elem.value)
    result := {
        "type": "sec_def_admin",
        "element": elem,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Host namespace sharing via CLI flag. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "volumes"
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    regex.match("^/[^:]*:/", elem.value)
    result := {
        "type": "sec_def_admin",
        "element": elem,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Host filesystem path mounted in container. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    entry.key.value == wildcard_perm_names[_]
    entry.value.ir_type == "String"
    entry.value.value == "*"
    result := {
        "type": "sec_def_admin",
        "element": entry.key,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Wildcard permission grants overly broad access. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    entry.key.value == wildcard_perm_names[_]
    entry.value.ir_type == "Array"
    elem := entry.value.value[_]
    elem.ir_type == "String"
    elem.value == "*"
    result := {
        "type": "sec_def_admin",
        "element": entry.key,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Wildcard permission in array grants overly broad access. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    regex.match(overprivileged_pattern, elem.value)
    result := {
        "type": "sec_def_admin",
        "element": elem,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Overprivileged role or policy assigned. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    entry := node.value[_]
    entry.key.ir_type == "String"
    entry.key.value == role_ref_keys[_]
    entry.value.ir_type == "String"
    regex.match(overprivileged_exact_pattern, entry.value.value)
    result := {
        "type": "sec_def_admin",
        "element": entry.value,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Overprivileged role or policy directly assigned. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, node])
    node.ir_type == "Hash"
    ref_entry := node.value[_]
    ref_entry.key.ir_type == "String"
    ref_entry.key.value == role_ref_keys[_]
    ref_entry.value.ir_type == "Hash"
    inner_entry := ref_entry.value.value[_]
    inner_entry.key.ir_type == "String"
    inner_entry.key.value == "name"
    inner_entry.value.ir_type == "String"
    regex.match(overprivileged_exact_pattern, inner_entry.value.value)
    result := {
        "type": "sec_def_admin",
        "element": inner_entry.value,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Overprivileged role referenced inside role reference block. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "acl"
    attr.value.ir_type == "String"
    attr.value.value == {"public-read-write", "publicReadWrite", "allUsers", "allAuthenticatedUsers"}[_]
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Resource ACL allows public or world-level access. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "network_mode"
    attr.value.ir_type == "String"
    attr.value.value == "host"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - network_mode set to host bypasses network isolation. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == {"content", "command", "cmd", "entrypoint", "args"}[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(\\bsudo\\b|--privileged|NOPASSWD\\s*:\\s*ALL|setuid|setgid)", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Privilege escalation pattern in command or content. (CWE-250)"
    }
}