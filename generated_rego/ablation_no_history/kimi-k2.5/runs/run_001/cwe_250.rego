package glitch

import data.glitch_lib

high_privilege_users := {"root", "admin", "administrator", "system", "sudo"}

user_attr_names := {"user", "username", "remote_user", "become_user", "run_as", "run_as_user"}

privilege_flag_attrs := {"privileged", "elevated", "become", "sudo", "run_as_root", "allow_privilege_escalation", "host_network", "host_pid", "host_ipc"}

priv_scope_attrs := {"scope", "resource", "action", "permissions", "role", "trust_policy"}

priv_scope_wildcards := {"*", "all"}

capability_attrs := {"capabilities", "cap_add", "allowed_capabilities"}

is_high_privilege_user(value) {
    value.ir_type == "String"
    regex.match("(?i)^\\s*(root|admin|administrator|system)\\s*$", value.value)
}

is_wildcard_scope(value) {
    value.ir_type == "String"
    regex.match("(?i)^\\s*(\\*|all|global)\\s*$", value.value)
}

is_privilege_flag_true(value) {
    value.ir_type == "Boolean"
    value.value == true
}

is_privilege_flag_true(value) {
    value.ir_type == "String"
    regex.match("(?i)^\\s*(true|yes|1)\\s*$", value.value)
}

contains_high_privilege_in_string(value) {
    value.ir_type == "String"
    regex.match("(?i)(^|\\s|=|@)root(@|[^.]|$)", value.value)
}

check_attr_value_privileged(attr) {
    lower(attr.name) == user_attr_names[_]
    is_high_privilege_user(attr.value)
}

check_attr_value_privileged(attr) {
    lower(attr.name) == privilege_flag_attrs[_]
    is_privilege_flag_true(attr.value)
}

check_attr_value_privileged(attr) {
    lower(attr.name) == priv_scope_attrs[_]
    is_wildcard_scope(attr.value)
}

check_attr_value_privileged(attr) {
    lower(attr.name) == "command"
    contains_high_privilege_in_string(attr.value)
}

check_attr_value_privileged(attr) {
    lower(attr.name) == capability_attrs[_]
    attr.value.ir_type == "Array"
    arr_elem := attr.value.value[_]
    arr_elem.ir_type == "String"
    regex.match("(?i)^\\s*(\\*|ALL|CAP_SYS_ADMIN)", arr_elem.value)
}

all_attrs_recursive(node) = attrs {
    attrs = {n |
        walk(node, [_, n])
        n.ir_type == "Attribute"
    }
}

all_expressions_recursive(node) = exprs {
    exprs = {n |
        walk(node, [_, n])
        n.ir_type == "String"
    }
}

check_string_expr_privileged(node) {
    node.ir_type == "String"
    regex.match("(?i)(^|\\s|=|@|:)root(@|[^.]|$)", node.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attrs := all_attrs_recursive(parent)
    attr := attrs[_]
    
    check_attr_value_privileged(attr)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Unauthorized privilege configuration detected. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    exprs := all_expressions_recursive(parent)
    expr := exprs[_]
    
    check_string_expr_privileged(expr)
    
    result := {
        "type": "sec_def_admin",
        "element": expr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Unauthorized privilege configuration detected. (CWE-250)"
    }
}