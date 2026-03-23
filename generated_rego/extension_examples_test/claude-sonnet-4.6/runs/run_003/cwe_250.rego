package glitch

import data.glitch_lib

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
        "description": "Container running in privileged mode grants full host access. (CWE-250)"
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
    regex.match("(?i)^(remote_)?user$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(root|0)$", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Service or process configured to run as root user. (CWE-250)"
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
        "description": "Privilege escalation is explicitly allowed. (CWE-250)"
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
        "description": "runAsNonRoot is false, allowing containers to run as root. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    {"hostpid", "hostipc", "hostnetwork", "shareprocessnamespace"}[lower(attr.name)]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container configured to share host namespaces, granting elevated host access. (CWE-250)"
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
        "description": "Container root filesystem is writable, enabling potential privilege abuse. (CWE-250)"
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
        "description": "Service account token auto-mounted, potentially granting excessive API access. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "add"
    attr.value.ir_type == "Array"
    cap := attr.value.value[_]
    cap.ir_type == "String"
    regex.match("(?i)^(ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE|DAC_OVERRIDE|SETUID|SETGID|SYS_MODULE)$", cap.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container granted dangerous Linux capabilities. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(actions?|verbs|resources?|nonresourceurls?)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("^(\\*|\\*:\\*)$", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive IAM/RBAC policy using wildcard permissions. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(actions?|verbs|resources?|nonresourceurls?)$", attr.name)
    attr.value.ir_type == "Array"
    item := attr.value.value[_]
    item.ir_type == "String"
    regex.match("^(\\*|\\*:\\*)$", item.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive IAM/RBAC policy using wildcard permissions. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "become"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Task configured to escalate privileges using become. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "become"
    attr.value.ir_type == "String"
    regex.match("(?i)^yes$", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Task configured to escalate privileges using become. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "become_user"
    attr.value.ir_type == "String"
    regex.match("(?i)^root$", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Task escalates to root user via become_user. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(db_?user|mysql_?user|postgres_?user|username)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)^(root|admin|sa|dba|sysadmin|postgres)$", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Service configured with administrative database credentials. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(seccomp.?profile|apparmor.?profile)$", attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)unconfined", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container security profile set to Unconfined, disabling security restrictions. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(command|cmd|shell|exec|run|script)$", attr.name)
    glitch_lib.traverse(attr.value, "(?i)root@")
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Command executes SSH connection as root user. (CWE-250)"
    }
}