package glitch

import data.glitch_lib

# Detect root user in Ansible cron tasks (Line 40)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "ansible.builtin.cron"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "user"
    attr.value.ir_type == "String"
    attr.value.value == "root"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Cron job running as root - Unnecessary root privileges for scheduled task. (CWE-250)"
    }
}

# Detect root ownership in Ansible copy resources (Lines 31, 32) - only when owner/group are explicitly root
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "ansible.builtin.copy"
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    (attr.name == "owner" or attr.name == "group")
    attr.value.ir_type == "String"
    attr.value.value == "root"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Resource owned by root - Unnecessary root privileges detected. (CWE-250)"
    }
}

# Detect global privilege escalation in Ansible (become: yes) - only when NOT explicitly owner/group root
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "become"
    attr.value.ir_type == "String"
    attr.value.value == "yes"
    # Ensure no root ownership is set in the same resource
    not has_root_owner(attrs)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privilege escalation enabled - Unnecessary elevated privileges detected. (CWE-250)"
    }
}

# Detect global privilege escalation in Ansible (become: true) - only when NOT explicitly owner/group root
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "become"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    # Ensure no root ownership is set in the same resource
    not has_root_owner(attrs)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privilege escalation enabled - Unnecessary elevated privileges detected. (CWE-250)"
    }
}

# Helper to check if root owner or group is set
has_root_owner(attrs) {
    attr := attrs[_]
    (attr.name == "owner" or attr.name == "group")
    attr.value.ir_type == "String"
    attr.value.value == "root"
}

# Detect root user in Chef execute resources (Line 16)
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
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Command executed as root - Unnecessary root privileges detected. (CWE-250)"
    }
}