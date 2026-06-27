package glitch

import data.glitch_lib

sensitive_path_pattern := `^(/|/etc|/proc|/sys|/var/run|/root|/home|/bin|/sbin|/usr|/boot|/dev|/lib)(/.*)?$`

is_sensitive_path(val) {
    val.ir_type == "String"
    regex.match(sensitive_path_pattern, val.value)
}

Glitch_Analysis[result] {
    input.path != ""
    walk(input, [_, ub])
    ub.ir_type == "UnitBlock"
    ub.line > 0
    regex.match(`(?i)volume_?mount`, ub.name)
    attr := ub.attributes[_]
    regex.match(`(?i)mount_?path`, attr.name)
    is_sensitive_path(attr.value)
    result := {
        "type": "sec_mount_write_permissions",
        "element": ub,
        "path": input.path,
        "description": "Sensitive host path mounted in container - Mounting sensitive host directories can lead to privilege escalation or container escape. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    input.path != ""
    walk(input, [_, attr])
    attr.ir_type == "Attribute"
    attr.line > 0
    regex.match(`(?i)volume_?mount`, attr.name)
    attr.value.ir_type == "Array"
    hash_entry := attr.value.value[_]
    hash_entry.ir_type == "Hash"
    kv := hash_entry.value[_]
    regex.match(`(?i)mount_?path`, kv.key.value)
    is_sensitive_path(kv.value)
    result := {
        "type": "sec_mount_write_permissions",
        "element": attr,
        "path": input.path,
        "description": "Sensitive host path mounted in container - Mounting sensitive host directories can lead to privilege escalation or container escape. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    input.path != ""
    walk(input, [_, ub])
    ub.ir_type == "UnitBlock"
    ub.line > 0
    regex.match(`(?i)host_?path`, ub.name)
    attr := ub.attributes[_]
    attr.name == "path"
    is_sensitive_path(attr.value)
    result := {
        "type": "sec_mount_write_permissions",
        "element": ub,
        "path": input.path,
        "description": "Sensitive host path mounted in container - Mounting sensitive host directories can lead to privilege escalation or container escape. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    input.path != ""
    walk(input, [_, attr])
    attr.ir_type == "Attribute"
    attr.line > 0
    regex.match(`(?i)host_?path`, attr.name)
    is_sensitive_path(attr.value)
    result := {
        "type": "sec_mount_write_permissions",
        "element": attr,
        "path": input.path,
        "description": "Sensitive host path mounted in container - Mounting sensitive host directories can lead to privilege escalation or container escape. (CWE-269)"
    }
}