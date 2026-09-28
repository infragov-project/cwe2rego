package glitch

import data.glitch_lib

priv_username_fields := {"username", "user", "admin_user", "db_username", "login", "administrator", "root_user", "master_username", "master_user", "db_admin", "admin_login", "db_user", "admin_username", "ssh_user", "default_user", "remote_user"}

priv_username_values := {"admin", "administrator", "root", "superuser", "sa", "postgres", "ubuntu", "ec2-user", "vagrant", "master", "dbo", "sys", "azureuser", "centos"}

priv_role_fields := {"role", "role_name", "iam_role", "assigned_roles", "permissions", "policy", "access_level", "privilege", "grant", "permission_set", "actions", "resource", "allow", "effect"}

priv_role_values := {"admin", "owner", "root", "superadmin", "fullaccess", "administratoraccess", "*"}

service_account_fields := {"service_account", "service_account_name", "run_as", "execution_role"}

service_account_values := {"default", "system:admin", "cluster-admin", "default-service-account", "root"}

attr_string_matches_any(value, values) {
    walk(value, [_, n])
    n.ir_type == "String"
    lower(n.value) == values[_]
}

attr_string_contains_pattern(value, pattern) {
    walk(value, [_, n])
    n.ir_type == "String"
    regex.match(pattern, n.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == priv_username_fields[_]
    attr_string_matches_any(attr.value, priv_username_values)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - Hardcoded privileged username detected. Violates Principle of Least Privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == priv_role_fields[_]
    attr_string_matches_any(attr.value, priv_role_values)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - Privileged role, policy, or wildcard permission detected. Violates Principle of Least Privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == service_account_fields[_]
    attr_string_matches_any(attr.value, service_account_values)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - Default or privileged service account detected. Violates Principle of Least Privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"privileged", "run_as_root"}[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - Container configured to run as privileged or root. Violates Principle of Least Privilege. (CWE-250)"
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
        "description": "Admin by Default - runAsNonRoot set to false allows container to run as root. Violates Principle of Least Privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == {"run_as_user", "runasuser"}[_]
    attr.value.ir_type == "Integer"
    attr.value.value == 0

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - Container running as root user (UID 0) detected. Violates Principle of Least Privilege. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr_string_contains_pattern(attr.value, "root@")

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - SSH connection as root user detected in command. Violates Principle of Least Privilege. (CWE-250)"
    }
}