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
    attr.name == "become"
    attr.value.ir_type == "String"
    attr.value.value == "yes"
    result := {"type": "sec_def_admin", "element": attr, "path": parent.path, "description": "Unnecessary privilege escalation - using become for non-privileged operations (CWE-250)"}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "ansible.builtin.user"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "groups"
    attr.value.ir_type == "String"
    regex.match(".*(sudo|wheel).*", attr.value.value)
    result := {"type": "sec_def_admin", "element": attr, "path": parent.path, "description": "Overly privileged user assignment - granting sudo/wheel access unnecessarily (CWE-250)"}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "execute"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "command"
    attr.value.ir_type == "String"
    regex.match(".*\\bsudo\\b.*", attr.value.value)
    result := {"type": "sec_def_admin", "element": attr, "path": parent.path, "description": "Unnecessary sudo usage in command (CWE-250)"}
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
    attr.value.value == "root"
    result := {"type": "sec_def_admin", "element": attr, "path": parent.path, "description": "Running command as root user unnecessarily (CWE-250)"}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "user"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "groups"
    attr.value.ir_type == "Array"
    some group in attr.value.value
    group.ir_type == "String"
    regex.match("^(sudo|wheel)$", group.value)
    result := {"type": "sec_def_admin", "element": attr, "path": parent.path, "description": "Overly privileged user assignment - granting sudo/wheel access unnecessarily (CWE-250)"}
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "exec"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "command"
    attr.value.ir_type == "String"
    regex.match(".*\\bsudo\\b.*", attr.value.value)
    result := {"type": "sec_def_admin", "element": attr, "path": parent.path, "description": "Unnecessary sudo usage in Puppet exec command (CWE-250)"}
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
    attr.value.value == "root"
    result := {"type": "sec_def_admin", "element": attr, "path": parent.path, "description": "Running exec as root unnecessarily (CWE-250)"}
}