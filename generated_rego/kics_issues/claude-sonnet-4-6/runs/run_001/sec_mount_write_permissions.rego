package glitch

import data.glitch_lib

sensitive_path_pattern := "^(/|/etc|/proc|/sys|/var/run|/root|/boot|/dev|/lib|/usr|/bin|/sbin|/run/containerd)(/.*)?$"

is_sensitive_path(value) {
    value.ir_type == "String"
    regex.match(sensitive_path_pattern, value.value)
}

volume_mount_names := {"volume_mount", "volumemount", "volumemounts", "volume_mounts"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, ub])
    ub.ir_type == "UnitBlock"
    lower(ub.name) == volume_mount_names[_]

    attrs := glitch_lib.all_attributes(ub)
    attr := attrs[_]
    lower(attr.name) == "mount_path"
    is_sensitive_path(attr.value)

    result := {
        "type": "sec_mount_write_permissions",
        "element": ub,
        "path": parent.path,
        "description": "Sensitive Host Path Volume Mount - Mounting sensitive host filesystem paths can escape container isolation and lead to privilege escalation or full host compromise. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, ub])
    ub.ir_type == "UnitBlock"
    lower(ub.name) == "host_path"

    attrs := glitch_lib.all_attributes(ub)
    attr := attrs[_]
    attr.name == "path"
    is_sensitive_path(attr.value)

    result := {
        "type": "sec_mount_write_permissions",
        "element": ub,
        "path": parent.path,
        "description": "Sensitive Host Path Volume Mount - Mounting sensitive host filesystem paths can escape container isolation and lead to privilege escalation or full host compromise. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    lower(attr.name) == "host_path"
    is_sensitive_path(attr.value)

    result := {
        "type": "sec_mount_write_permissions",
        "element": attr,
        "path": parent.path,
        "description": "Sensitive Host Path Volume Mount - Mounting sensitive host filesystem paths can escape container isolation and lead to privilege escalation or full host compromise. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""

    walk(parent, [_, attr])
    attr.ir_type == "Attribute"
    lower(attr.name) == volume_mount_names[_]
    attr.value.ir_type == "Array"

    entry := attr.value.value[_]
    entry.ir_type == "Hash"

    kv := entry.value[_]
    kv.key.ir_type == "VariableReference"
    lower(kv.key.value) == "mount_path"
    is_sensitive_path(kv.value)

    result := {
        "type": "sec_mount_write_permissions",
        "element": attr,
        "path": parent.path,
        "description": "Sensitive Host Path Volume Mount - Mounting sensitive host filesystem paths can escape container isolation and lead to privilege escalation or full host compromise. (CWE-269)"
    }
}