package glitch

import data.glitch_lib

privileged_keywords := {"privileged", "user", "runAsUser", "runAsNonRoot", "runAsGroup", "owner", "group", "mode", "permissions", "securityContext", "capabilities", "security_opt", "remote_user", "sudo_user", "become_user", "become", "sudo", "su"}

overly_permissive_values := {"root", "admin", "superuser", "world-readable", "world-writeable", "read_write", "full_control", "execute", "all", "*"}

overly_permissive_modes := {"0777", "0666", "777", "666"}

dangerous_caps := {"all", "sys_admin", "sys_ptrace", "net_admin", "sys_time", "sys_module"}

admin_users := {"root", "admin"}

command_attr_names := {"command", "cmd", "script", "inline_script", "inline", "cmd_script"}

become_user_keywords := {"ansible_become_user", "become_user", "sudo_user"}

privilege_escalation_pattern := `(?i)(root@|sudo\s|su\s+-|/bin/su\s|chown\s+root|chmod\s+[0-7]*7[0-7]*\s|/etc/shadow|passwd\s)`

check_privilege_pattern(attr) {
    attr.value.ir_type == "String"
    lower(attr.value.value) == overly_permissive_values[_]
} else {
    attr.value.ir_type == "String"
    attr.value.value == overly_permissive_modes[_]
} else {
    attr.value.ir_type == "Boolean"
    attr.name == "privileged"
    attr.value.value == true
} else {
    attr.value.ir_type == "Boolean"
    attr.name == "runAsNonRoot"
    attr.value.value == false
}

is_dangerous_cap(cap) {
    cap == dangerous_caps[_]
}

has_dangerous_cap_value(value) {
    value.ir_type == "Array"
    cap := value.value[_]
    cap.ir_type == "String"
    is_dangerous_cap(lower(cap.value))
} else {
    value.ir_type == "Hash"
    walk(value.value, [_, v])
    v.ir_type == "String"
    is_dangerous_cap(lower(v.value))
} else {
    value.ir_type == "String"
    is_dangerous_cap(lower(value.value))
}

has_privilege_pattern_in_expr(expr) {
    walk(expr, [_, node])
    node.ir_type == "String"
    regex.match(privilege_escalation_pattern, node.value)
}

is_admin_user(u) {
    u == admin_users[_]
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == privileged_keywords[_]
    check_privilege_pattern(attr)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive privilege assignment without justification - Resources should follow the principle of least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    ub := parent.unit_blocks[_]
    attrs := glitch_lib.all_attributes(ub)
    attr := attrs[_]
    attr.name == privileged_keywords[_]
    check_privilege_pattern(attr)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive privilege assignment without justification - Resources should follow the principle of least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "capabilities"
    has_dangerous_cap_value(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly broad permission grants in capabilities - Capabilities should be minimized. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    ub := parent.unit_blocks[_]
    attrs := glitch_lib.all_attributes(ub)
    attr := attrs[_]
    attr.name == "capabilities"
    has_dangerous_cap_value(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly broad permission grants in capabilities - Capabilities should be minimized. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == command_attr_names[_]
    has_privilege_pattern_in_expr(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Command contains privilege escalation pattern - Avoid using root or sudo in commands without justification. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    ub := parent.unit_blocks[_]
    attrs := glitch_lib.all_attributes(ub)
    attr := attrs[_]
    attr.name == command_attr_names[_]
    has_privilege_pattern_in_expr(attr.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Command contains privilege escalation pattern - Avoid using root or sudo in commands without justification. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "variables"
    attr.value.ir_type == "Hash"
    walk(attr.value.value, [path, v])
    count(path) > 0
    k := path[count(path) - 1]
    is_string(k)
    lower(k) == "become"
    v.ir_type == "Boolean"
    v.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privilege escalation via become/sudo without constraints - Avoid unrestricted privilege escalation. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    ub := parent.unit_blocks[_]
    attrs := glitch_lib.all_attributes(ub)
    attr := attrs[_]
    attr.name == "variables"
    attr.value.ir_type == "Hash"
    walk(attr.value.value, [path, v])
    count(path) > 0
    k := path[count(path) - 1]
    is_string(k)
    lower(k) == "become"
    v.ir_type == "Boolean"
    v.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privilege escalation via become/sudo without constraints - Avoid unrestricted privilege escalation. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "variables"
    attr.value.ir_type == "Hash"
    walk(attr.value.value, [path, v])
    count(path) > 0
    k := path[count(path) - 1]
    is_string(k)
    lower(k) == become_user_keywords[_]
    v.ir_type == "String"
    is_admin_user(lower(v.value))
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Default admin credentials detected - Avoid using default credentials. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    ub := parent.unit_blocks[_]
    attrs := glitch_lib.all_attributes(ub)
    attr := attrs[_]
    attr.name == "variables"
    attr.value.ir_type == "Hash"
    walk(attr.value.value, [path, v])
    count(path) > 0
    k := path[count(path) - 1]
    is_string(k)
    lower(k) == become_user_keywords[_]
    v.ir_type == "String"
    is_admin_user(lower(v.value))
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Default admin credentials detected - Avoid using default credentials. (CWE-250)"
    }
}