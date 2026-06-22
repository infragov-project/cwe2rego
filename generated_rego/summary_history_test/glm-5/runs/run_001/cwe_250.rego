package glitch

import data.glitch_lib

user_context_attrs := {"run_as", "user", "run_as_user", "uid", "gid", "effective_user", "service_account", "remote_user", "become_user", "owner"}
privilege_escalation_attrs := {"privileged", "allow_privilege_escalation", "escalate", "become"}
mitigation_attrs := {"no_new_privs"}
capability_attrs := {"capabilities", "add_capabilities", "sysctls"}
policy_attrs := {"policy", "actions", "permissions", "role_definition"}
command_attrs := {"command", "cmd", "exec", "inline"}

dangerous_capabilities := {"sys_admin", "net_admin", "all", "*", "administratoraccess"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    attr := glitch_lib.all_attributes(parent)[_]

    check_cwe250_violation(attr)

    result := {{
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Execution with Unnecessary Privileges - Attribute '%s' grants excessive permissions. (CWE-250)", [attr.name])
    }}
}

check_cwe250_violation(attr) {
    attr.name == user_context_attrs[_]
    is_root_user(attr.value)
}

check_cwe250_violation(attr) {
    attr.name == privilege_escalation_attrs[_]
    glitch_lib.traverse(attr.value, true)
}

check_cwe250_violation(attr) {
    attr.name == mitigation_attrs[_]
    glitch_lib.traverse(attr.value, false)
}

check_cwe250_violation(attr) {
    attr.name == capability_attrs[_]
    glitch_lib.traverse(attr.value, dangerous_capabilities)
}

check_cwe250_violation(attr) {
    attr.name == policy_attrs[_]
    glitch_lib.traverse(attr.value, "*")
}

check_cwe250_violation(attr) {
    attr.name == command_attrs[_]
    glitch_lib.traverse(attr.value, "(?i).*root@.*")
}

is_root_user(value) {
    glitch_lib.traverse(value, "root")
}

is_root_user(value) {
    glitch_lib.traverse(value, "0")
}

is_root_user(value) {
    value.ir_type == "Integer"
    value.value == 0
}