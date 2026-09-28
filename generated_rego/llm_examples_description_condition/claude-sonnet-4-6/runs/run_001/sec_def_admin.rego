package glitch

import data.glitch_lib

is_username_field(name) {
    regex.match("(?i)(user|username|default_user|master_username|db_user|login_name|initial_user|bootstrap_user|admin_login|admin_user|ssh_user|master_user|db_master_user|superuser_login|run_as|run_as_user)", name)
}

is_privileged_identity(value) {
    regex.match("(?i)^(admin|administrator|root|superuser|sa|dba)$", value)
}

is_privileged_password_field(name) {
    regex.match("(?i).*(admin|root|master|superuser|postgres|dba|sa).*(password|passwd|pwd|hash).*", name)
}

is_role_field(name) {
    regex.match("(?i)^(role|roles|administrator_role|root_role|account_type|account_role|user_role|owner_role)$", name)
}

is_admin_flag(name) {
    regex.match("(?i)^(is_admin|admin_enabled|admin_access|privileged|run_as_root|grant_all|full_access|attach_admin_policy|admin_group|billing_admin|grant_option|superuser)$", name)
}

is_privileged_group(value) {
    regex.match("(?i)^(admin|administrators|sudo|root|superuser|dba)$", value)
}

is_admin_policy_value(value) {
    regex.match("(?i)(administrator.?access|admin.?policy|full.?admin)", value)
}

is_content_attr(name) {
    regex.match("(?i)^(content|command|line|value|template|script|source|cmd)$", name)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_username_field(attr.name)
    attr.value.ir_type == "String"
    is_privileged_identity(attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - A privileged username is used by default, violating the Principle of Least Privilege. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_username_field(v.name)
    v.value.ir_type == "String"
    is_privileged_identity(v.value.value)
    result := {
        "type": "sec_def_admin",
        "element": v,
        "path": parent.path,
        "description": "Admin by Default - A privileged username variable is defined, violating the Principle of Least Privilege. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_privileged_password_field(attr.name)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - A privileged password field is configured, indicating an admin/root account setup. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_privileged_password_field(v.name)
    result := {
        "type": "sec_def_admin",
        "element": v,
        "path": parent.path,
        "description": "Admin by Default - A privileged password variable is defined, indicating an admin/root account setup. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i).*(password|passwd|pwd|password_hash).*", attr.name)
    attr.value.ir_type == "FunctionCall"
    arg := attr.value.args[_]
    arg.ir_type == "String"
    is_privileged_identity(arg.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - A password function is called with a privileged identity argument. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    is_username_field(entry.key.value)
    entry.value.ir_type == "String"
    is_privileged_identity(entry.value.value)
    result := {
        "type": "sec_def_admin",
        "element": entry.value,
        "path": parent.path,
        "description": "Admin by Default - A privileged username is configured inside a hash, violating the Principle of Least Privilege. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    not regex.match("(?i)^env$", attr.name)
    elem := attr.value.value[_]
    elem.ir_type == "String"
    is_privileged_group(elem.value)
    result := {
        "type": "sec_def_admin",
        "element": elem,
        "path": parent.path,
        "description": "Admin by Default - A privileged group membership is assigned, violating the Principle of Least Privilege. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "String"
    regex.match("(?i)(RUN_AS_ROOT|SSH_USER|RUN_AS|SUDO_USER|RUN_AS_NONROOT)\\s*=\\s*(true|1|root|yes)", elem.value)
    result := {
        "type": "sec_def_admin",
        "element": elem,
        "path": parent.path,
        "description": "Admin by Default - Environment variable sets a privileged execution context, violating the Principle of Least Privilege. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    aus := glitch_lib.all_atomic_units(parent)
    au := aus[_]
    au.name.ir_type == "String"
    is_privileged_identity(au.name.value)
    result := {
        "type": "sec_def_admin",
        "element": au,
        "path": parent.path,
        "description": "Admin by Default - A resource is named with a privileged identity, violating the Principle of Least Privilege. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_content_attr(attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)PermitRootLogin\\s+yes", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - SSH is configured to permit root login, violating the Principle of Least Privilege. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_content_attr(attr.name)
    attr.value.ir_type == "String"
    regex.match("(?i)NOPASSWD.*ALL", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - Passwordless sudo with unrestricted access is configured, violating the Principle of Least Privilege. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_role_field(attr.name)
    attr.value.ir_type == "String"
    is_privileged_identity(attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - An administrative role is assigned by default, violating the Principle of Least Privilege. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_admin_flag(attr.name)
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - An administrative privilege flag is enabled, violating the Principle of Least Privilege. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^privileges?$", attr.name)
    attr.value.ir_type == "Array"
    elem := attr.value.value[_]
    elem.ir_type == "VariableReference"
    regex.match("(?i):?all$", elem.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - All privileges are granted, violating the Principle of Least Privilege. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    walk(attr.value, [_, hash_node])
    hash_node.ir_type == "Hash"
    entry := hash_node.value[_]
    entry.key.ir_type == "String"
    regex.match("(?i)^(action|policy|permission)$", entry.key.value)
    entry.value.ir_type == "String"
    entry.value.value == "*"
    result := {
        "type": "sec_def_admin",
        "element": entry.value,
        "path": parent.path,
        "description": "Admin by Default - Wildcard action permissions are assigned in a policy document, granting unrestricted access. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    is_admin_policy_value(attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - An administrator-level policy is referenced, violating the Principle of Least Privilege. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    regex.match("(?i)^(uid|run_?as_?user|runas_?user|runasuser|security_context_run_as_user)$", attr.name)
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - Process configured to run as root (UID 0), violating the Principle of Least Privilege. (CWE-1188)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    aus := glitch_lib.all_atomic_units(parent)
    au := aus[_]
    not regex.match("(?i)^file$", au.type)
    attr := au.attributes[_]
    regex.match("(?i)^(gid|group)$", attr.name)
    attr.value.ir_type == "String"
    is_privileged_identity(attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin by Default - Process configured with a privileged group, violating the Principle of Least Privilege. (CWE-1188)"
    }
}