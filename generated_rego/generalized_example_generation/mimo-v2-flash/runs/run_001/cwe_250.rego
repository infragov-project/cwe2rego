package glitch

import data.glitch_lib

privileged_users := {"root", "admin", "administrator", "sudo", "wheel", "ALL"}
command_types := {"command", "shell", "execute", "exec", "sudo"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "command"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "become"
    attr.value.ir_type == "String"
    attr.value.value == "yes"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privilege escalation enabled via become - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "shell"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "become"
    attr.value.ir_type == "String"
    attr.value.value == "yes"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privilege escalation enabled via become - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "command"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "become_user"
    attr.value.ir_type == "String"
    privileged_users[attr.value.value]
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Running as privileged user via become_user - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "shell"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "become_user"
    attr.value.ir_type == "String"
    privileged_users[attr.value.value]
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Running as privileged user via become_user - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "execute"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "user"
    attr.value.ir_type == "String"
    privileged_users[attr.value.value]
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Running as privileged user - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "exec"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "user"
    attr.value.ir_type == "String"
    privileged_users[attr.value.value]
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Running as privileged user - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "sudo"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "host"
    attr.value.ir_type == "String"
    attr.value.value == "ALL"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Sudo host set to ALL - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "sudo"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "run_as"
    attr.value.ir_type == "String"
    attr.value.value == "ALL"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Sudo run_as set to ALL - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "file"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "content"
    attr.value.ir_type == "String"
    regex.match(".*ALL.*NOPASSWD.*", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Sudoers file with NOPASSWD and ALL - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "command"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "command"
    attr.value.ir_type == "String"
    regex.match(".*sudo.*", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Command uses sudo - This may indicate unnecessary privilege escalation. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "shell"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "shell"
    attr.value.ir_type == "String"
    regex.match(".*sudo.*", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Shell command uses sudo - This may indicate unnecessary privilege escalation. (CWE-250)"
    }
}