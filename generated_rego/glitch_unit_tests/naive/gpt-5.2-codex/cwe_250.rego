package glitch

import data.glitch_lib

normalize(s) = out {
    lower_s := lower(s)
    no_dash := replace(lower_s, "-", "")
    out := replace(no_dash, "_", "")
}

is_kv(kv) {
    kv.ir_type == "Attribute"
    kv.value.ir_type != "BlockExpr"
}

is_kv(kv) {
    kv.ir_type == "Variable"
    kv.value.ir_type != "BlockExpr"
}

is_true(v) {
    v.ir_type == "Boolean"
    v.value == true
}

is_true(v) {
    v.ir_type == "String"
    regex.match("(?i)^(true|yes|1)$", v.value)
}

is_true(v) {
    v.ir_type == "Integer"
    v.value == 1
}

is_zero(v) {
    v.ir_type == "Integer"
    v.value == 0
}

is_zero(v) {
    v.ir_type == "String"
    regex.match("^0$", v.value)
}

value_matches_regex(v, pattern) {
    glitch_lib.traverse(v, pattern)
}

is_root_value(v) {
    is_zero(v)
}

is_root_value(v) {
    value_matches_regex(v, priv_user_regex)
}

priv_user_regex := "(?i).*\\b(root|administrator|admin|superuser|owner)\\b.*"
priv_role_regex := "(?i).*(cluster-admin|account-admin|organization-admin|admin|administrator|owner|superuser|fullaccess).*"
wildcard_regex := "(?i).*(\\*|\\ball\\b|fullaccess|administrator|owner|superuser).*"
capability_regex := "(?i).*(\\ball\\b|sys_admin|cap_sys_admin).*"
hostpath_value_regex := "(?i)(^/$|^c:\\\\$|.*docker\\.sock.*)"
credential_key_regex := "^(admin|root|superuser).*password$"

user_keys := {"user","runasuser","uid","gid","username","userid","groupid","runasgroup","becomeuser"}
privileged_bool_keys := {"privileged","allowprivilegeescalation","hostnetwork","hostpid","hostipc","elevated","sudo","setuid","setgid","readwrite","readwriteonce","admin","become"}
capability_keys := {"capabilities","capability","capadd"}
perm_keys := {"permissions","actions","resources","resource","policy","policies","role","roles","statement","effect","permission","privileges","privilege"}
service_keys := {"serviceaccount","serviceaccountname","rolebinding","principal","member"}
hostpath_keys := {"hostpath","hostvolume","hostmount","hostfilesystem"}
path_keys := {"mountpath","path","device","mount","volume"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    is_kv(kv)
    key := normalize(kv.name)
    key == user_keys[_]
    is_root_value(kv.value)

    result := {
        "type": "sec_def_admin",
        "element": kv,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - workload configured to run as root/administrator or UID 0. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    is_kv(kv)
    key := normalize(kv.name)
    key == privileged_bool_keys[_]
    is_true(kv.value)

    result := {
        "type": "sec_def_admin",
        "element": kv,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - privileged/host namespace access or privilege escalation enabled. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    is_kv(kv)
    key := normalize(kv.name)
    key == capability_keys[_]
    value_matches_regex(kv.value, capability_regex)

    result := {
        "type": "sec_def_admin",
        "element": kv,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Linux capabilities set to ALL or SYS_ADMIN. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    is_kv(kv)
    key := normalize(kv.name)
    key == perm_keys[_]
    value_matches_regex(kv.value, wildcard_regex)

    result := {
        "type": "sec_def_admin",
        "element": kv,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - overly broad IAM permissions (wildcards/full access). (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    is_kv(kv)
    key := normalize(kv.name)
    key == service_keys[_]
    value_matches_regex(kv.value, priv_role_regex)

    result := {
        "type": "sec_def_admin",
        "element": kv,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - service account bound to admin-level role. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    is_kv(kv)
    key := normalize(kv.name)
    key == hostpath_keys[_]

    result := {
        "type": "sec_def_admin",
        "element": kv,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - host filesystem or device access enabled. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    is_kv(kv)
    key := normalize(kv.name)
    key == path_keys[_]
    value_matches_regex(kv.value, hostpath_value_regex)

    result := {
        "type": "sec_def_admin",
        "element": kv,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - host filesystem or device access enabled. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, kv])
    is_kv(kv)
    key := normalize(kv.name)
    regex.match(credential_key_regex, key)

    result := {
        "type": "sec_def_admin",
        "element": kv,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - superuser credentials referenced. (CWE-250)"
    }
}