package glitch

import data.glitch_lib

iam_wildcard_keys := {"action", "resource", "notaction", "notresource"}

priv_true_attrs := {
    "privileged", "allowprivilegeescalation", "allow_privilege_escalation",
    "hostpid", "host_pid", "hostipc", "host_ipc",
    "hostnetwork", "host_network", "automountserviceaccounttoken",
    "become", "privileged_mode", "enable_privileged"
}

sec_false_attrs := {
    "readonlyrootfilesystem", "read_only_root_filesystem",
    "runasnonroot", "run_as_non_root"
}

user_root_attrs := {"user", "become_user", "run_as_user", "runasuser", "run_as"}

script_content_attrs := {"code", "shell", "inline", "script_body", "content"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == priv_true_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Privileged or elevated access enabled. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == sec_false_attrs[_]
    attr.value.ir_type == "Boolean"
    attr.value.value == false
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Security feature disabled. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == user_root_attrs[_]
    attr.value.ir_type == "String"
    lower(attr.value.value) == "root"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Process running as root user. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    lower(attr.name) == script_content_attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)\\bsudo\\b", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Sudo usage detected in script content. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    cmd_attr := attrs[_]
    cmd_attr.value.ir_type == "String"
    regex.match("(?i)\\bsudo\\b", cmd_attr.value.value)
    path_attr := attrs[_]
    lower(path_attr.name) == "path"
    path_attr.value.ir_type == "String"
    result := {
        "type": "sec_def_admin",
        "element": path_attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Exec path configured for privileged sudo execution. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    pair := hash_node.value[_]
    pair.key.ir_type == "String"
    lower(pair.key.value) == iam_wildcard_keys[_]
    pair.value.ir_type == "String"
    pair.value.value == "*"
    result := {
        "type": "sec_def_admin",
        "element": pair.value,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - IAM policy with wildcard permissions. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [_, hash_node])
    hash_node.ir_type == "Hash"
    effect_pair := hash_node.value[_]
    effect_pair.key.ir_type == "String"
    lower(effect_pair.key.value) == "effect"
    effect_pair.value.ir_type == "String"
    lower(effect_pair.value.value) == "allow"
    wildcard_pair := hash_node.value[_]
    wildcard_pair.key.ir_type == "String"
    lower(wildcard_pair.key.value) == iam_wildcard_keys[_]
    wildcard_pair.value.ir_type == "String"
    wildcard_pair.value.value == "*"
    result := {
        "type": "sec_def_admin",
        "element": effect_pair.value,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - IAM Allow policy with wildcard permissions. (CWE-250)"
    }
}