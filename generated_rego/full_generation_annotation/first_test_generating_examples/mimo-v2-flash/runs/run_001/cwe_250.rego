package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "ansible.builtin.file"

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "become"
    attr.value.ir_type == "String"
    attr.value.value == "yes"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "High-Privilege Execution Context - Ansible become privilege escalation. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "ansible.builtin.shell"

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "become"
    attr.value.ir_type == "String"
    attr.value.value == "yes"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "High-Privilege Execution Context - Ansible become privilege escalation. (CWE-250)"
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

    attr.name == "owner"
    attr.value.ir_type == "String"
    attr.value.value == "root"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "High-Privilege Execution Context - File owner set to root. (CWE-250)"
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

    attr.name == "group"
    attr.value.ir_type == "String"
    attr.value.value == "root"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "High-Privilege Execution Context - File group set to root. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "execute"

    result := {
        "type": "sec_def_admin",
        "element": node,
        "path": parent.path,
        "description": "High-Privilege Execution Context - Chef execute resource defaults to root. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "exec"

    result := {
        "type": "sec_def_admin",
        "element": node,
        "path": parent.path,
        "description": "High-Privilege Execution Context - Puppet exec resource defaults to root. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    node.type == "sudo::conf"

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    attr.name == "content"
    attr.value.ir_type == "String"
    regex.match(".*\\(ALL\\).*NOPASSWD.*ALL.*", attr.value.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive IAM Permissions - Sudoers configuration allows NOPASSWD for all commands. (CWE-250)"
    }
}