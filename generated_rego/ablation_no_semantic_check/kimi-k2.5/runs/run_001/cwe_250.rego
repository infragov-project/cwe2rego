package glitch

import data.glitch_lib

privileged_keywords := {"root", "admin", "administrator", "system", "privileged", "elevation", "impersonation", "run_as", "assume_role", "admin_role", "full_access"}

wildcard_patterns := {"*", "**", "/*", "*/*"}

privileged_capabilities := {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "DAC_OVERRIDE"}

security_context_keys := {"security_context", "privileged", "allow_privilege_escalation", "run_as_user", "capabilities", "host_network", "host_pid", "host_ipc", "privileged_mode"}

is_privileged_true(value) {
    value.ir_type == "Boolean"
    value.value == true
} else {
    value.ir_type == "String"
    lower(value.value) == "true"
}

is_run_as_root(value) {
    value.ir_type == "String"
    regex.match("^(root|0)$", value.value)
} else {
    value.ir_type == "Integer"
    value.value == 0
}

has_wildcard_permission(value) {
    value.ir_type == "String"
    regex.match(`^\s*\*\s*$`, value.value)
}

has_privileged_keyword(value) {
    value.ir_type == "String"
    l := lower(value.value)
    contains(l, privileged_keywords[_])
}

contains(str, substr) {
    regex.match(sprintf(".*%s.*", [substr]), str)
}

check_capabilities(value) {
    value.ir_type == "String"
    contains(upper(value.value), privileged_capabilities[_])
} else {
    value.ir_type == "Array"
    v := value.value[_]
    v.ir_type == "String"
    contains(upper(v.value), privileged_capabilities[_])
}

check_hash_for_wildcards(value) {
    value.ir_type == "Hash"
    v := value.value[_]
    has_wildcard_permission(v)
}

check_array_for_wildcards(value) {
    value.ir_type == "Array"
    v := value.value[_]
    has_wildcard_permission(v)
}

is_security_context_attr(name) {
    contains(lower(name), security_context_keys[_])
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_security_context_attr(attr.name)
    is_privileged_true(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Privileged mode or privilege escalation is enabled, violating the principle of least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_security_context_attr(attr.name)
    is_run_as_root(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Running as root or user 0 without justification, violating the principle of least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    is_security_context_attr(attr.name)
    check_capabilities(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Dangerous capabilities granted, violating the principle of least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    lower(attr.name) == "role"
    has_privileged_keyword(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Administrative or privileged role assigned without least privilege justification. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    lower(attr.name) == "user"
    has_privileged_keyword(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Privileged user account configured, violating the principle of least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    regex.match(`(?i)(policy|permission|action|resource)`, attr.name)
    check_hash_for_wildcards(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Wildcard permissions in policy actions or resources, violating the principle of least privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    regex.match(`(?i)(policy|permission|action|resource)`, attr.name)
    check_array_for_wildcards(attr.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Wildcard permissions in policy actions or resources array, violating the principle of least privilege. (CWE-250)"
    }
}