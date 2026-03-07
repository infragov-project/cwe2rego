package glitch

import data.glitch_lib
import future.keywords.in

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "ansible.builtin.copy"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "content"
    attr.value.ir_type == "String"
    regex.match("(?i)User=root", attr.value.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Systemd service runs as root (User=root) in systemd unit file - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "ansible.builtin.copy"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "content"
    attr.value.ir_type == "String"
    regex.match("(?i)Group=root", attr.value.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Systemd service runs as root (Group=root) in systemd unit file - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "systemd_service"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "user"
    attr.value.ir_type == "String"
    attr.value.value == "root"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Systemd service runs as root (user attribute) - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "systemd_service"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "group"
    attr.value.ir_type == "String"
    attr.value.value == "root"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Systemd service runs as root (group attribute) - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "ansible.builtin.command"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "become"
    attr.value.ir_type == "String"
    attr.value.value == "yes"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Command uses privilege escalation (become: yes) - This may allow unnecessary privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "ruby_block"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "block"
    attr.value.ir_type == "BlockExpr"
    walk(attr.value, [_, n])
    n.ir_type == "MethodCall"
    n.method == "new"
    n.receiver.value == "Mixlib::ShellOut"
    count(n.args) > 0
    arg := n.args[0]
    arg.ir_type == "String"
    regex.match(".*apt-get.*install.*", arg.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Ruby block executes privileged command (apt-get install) - This may allow unnecessary privileges. (CWE-250)"
    }
}