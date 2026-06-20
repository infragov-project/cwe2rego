package glitch

import data.glitch_lib

has_integer_zero(node) {
    walk(node, [_, n])
    n.ir_type == "Integer"
    n.value == 0
}

check_root_user(value) {
    glitch_lib.traverse(value, "(?i)^(root|0)$")
} else {
    value.ir_type == "Integer"
    value.value == 0
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(actions?|notactions?|resources?|notresources?|principal)$", attr.name)
    glitch_lib.traverse(attr.value, "^\\*$")
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly permissive IAM policy with wildcard '*' - Policies granting unrestricted access to all actions or resources are dangerous. (CWE-732)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(privileged|allow.?privilege.?escalation|host.?pid|host.?ipc|host.?network)$", attr.name)
    glitch_lib.traverse(attr.value, true)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged container mode enabled - Containers should not run with elevated host-level privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(run.?as.?user|run.?as.?group|fs.?group|supplemental.?groups?)$", attr.name)
    has_integer_zero(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Workload configured to run as root (UID 0) - Services and containers should not run as the root user. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(remote_)?user$", attr.name)
    check_root_user(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Service or container configured to run as root user - Avoid running as the root user. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(command|cmd)$", attr.name)
    glitch_lib.traverse(attr.value, "(?i).*root@.*")
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Command executing as root user - Commands referencing root@ indicate execution as the root user. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^run.?as.?non.?root$", attr.name)
    glitch_lib.traverse(attr.value, false)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "runAsNonRoot set to false - Containers should be configured to run as non-root users. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "acl"
    glitch_lib.traverse(attr.value, "(?i)^(public-read|public-read-write|authenticated-read)$")
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Storage bucket with a public ACL - Buckets should not be configured with public access. (CWE-732)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(block.?public.?(acls?|policy)|ignore.?public.?acls?|restrict.?public.?buckets?)$", attr.name)
    glitch_lib.traverse(attr.value, false)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Storage public access block disabled - Public access controls for storage buckets should not be disabled. (CWE-732)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "role"
    glitch_lib.traverse(attr.value, "(?i)^(admin|edit|cluster.?admin)$")
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly broad role binding - Binding to admin or cluster-admin roles grants excessive privileges. (CWE-732)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(policy.?arns?|managed.?policy.?arns?)$", attr.name)
    glitch_lib.traverse(attr.value, "(?i)(AdministratorAccess|FullAccess|PowerUserAccess)")
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly broad policy attachment - Binding to administrator or full-access policies grants excessive privileges. (CWE-732)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == "add"
    glitch_lib.traverse(attr.value, "(?i)^(all|sys.?admin|net.?admin)$")
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Dangerous Linux capability added - Adding ALL, SYS_ADMIN or NET_ADMIN capabilities grants excessive host-level privileges. (CWE-250)"
    }
}