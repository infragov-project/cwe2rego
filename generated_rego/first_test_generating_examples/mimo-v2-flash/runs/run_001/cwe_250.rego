package glitch

import data.glitch_lib

# Helper to check for excessive permissions in attributes
has_explicit_excessive_permission(attrs) {
    attr := attrs[_]
    attr.name == "mode"
    attr.value.ir_type == "String"
    attr.value.value == "0777"
}

has_explicit_excessive_permission(attrs) {
    attr := attrs[_]
    attr.name == "mode"
    attr.value.ir_type == "String"
    attr.value.value == "0666"
}

has_explicit_excessive_permission(attrs) {
    attr := attrs[_]
    attr.name == "command"
    attr.value.ir_type == "String"
    regex.match("chmod\\s+0?[67][67][67]", attr.value.value)
}

# Rule 1: Detect Excessive File Permissions (Mode 0777)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "mode"
    attr.value.ir_type == "String"
    attr.value.value == "0777"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive file permissions (0777) detected. (CWE-250)"
    }
}

# Rule 2: Detect Excessive File Permissions (Mode 0666)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "mode"
    attr.value.ir_type == "String"
    attr.value.value == "0666"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive file permissions (0666) detected. (CWE-250)"
    }
}

# Rule 3: Detect Excessive chmod Commands (666)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "command"
    attr.value.ir_type == "String"
    regex.match("chmod\\s+0?666", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive chmod 666 command detected. (CWE-250)"
    }
}

# Rule 4: Detect Excessive chmod Commands (777)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "command"
    attr.value.ir_type == "String"
    regex.match("chmod\\s+0?777", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive chmod 777 command detected. (CWE-250)"
    }
}

# Rule 5: Detect Ansible become: yes (Privilege Escalation Context)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    attr := parent.attributes[_]
    attr.name == "become"
    attr.value.ir_type == "String"
    attr.value.value == "yes"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Ansible become set to yes (running as root). (CWE-250)"
    }
}

# Rule 6: Detect Root Owner (Only if no excessive permissions in the same unit)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    not has_explicit_excessive_permission(attrs)
    attr := attrs[_]
    attr.name == "owner"
    attr.value.ir_type == "String"
    attr.value.value == "root"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Owner set to root. (CWE-250)"
    }
}

# Rule 7: Detect Root Group (Only if no excessive permissions in the same unit)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    not has_explicit_excessive_permission(attrs)
    attr := attrs[_]
    attr.name == "group"
    attr.value.ir_type == "String"
    attr.value.value == "root"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Group set to root. (CWE-250)"
    }
}

# Rule 8: Detect runAsUser: 0
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "runAsUser"
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Running as root user (UID 0). (CWE-250)"
    }
}

# Rule 9: Detect privileged container
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "privileged"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged container mode enabled. (CWE-250)"
    }
}

# Rule 10: Detect Admin Account Creation Attributes
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    attr.name == "admin_username"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Administrative account creation detected. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    attr.name == "administratorLogin"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Administrative account creation detected. (CWE-250)"
    }
}

# Rule 11: Detect Broad Role Assignments
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    attr.name == "role"
    regex.match("(?i)cluster-admin|administrator|root|superuser|db_admin", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Broad role assignment detected. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    attr.name == "privileges"
    regex.match("(?i)cluster-admin|administrator|root|superuser|db_admin", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Broad role assignment detected. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    attr.name == "access"
    regex.match("(?i)cluster-admin|administrator|root|superuser|db_admin", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Broad role assignment detected. (CWE-250)"
    }
}

# Rule 12: Detect Sudo Usage
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)sudo", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Use of sudo in command. (CWE-250)"
    }
}

# Rule 13: Detect Sensitive Capabilities
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)SYS_ADMIN|NET_ADMIN|\\bALL\\b", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Sensitive capability detected. (CWE-250)"
    }
}

# Rule 14: Detect Sensitive Host Paths
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    attr.name == "hostPath"
    regex.match("(?i)/var/run/docker.sock|/etc/passwd|/proc|/root", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Sensitive host path mounted. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    attr.name == "volume"
    regex.match("(?i)/var/run/docker.sock|/etc/passwd|/proc|/root", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Sensitive host path mounted. (CWE-250)"
    }
}

# Rule 15: Detect Admin Content
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    attr.name == "content"
    regex.match("(?i)admin", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Admin content detected. (CWE-250)"
    }
}

# Rule 16: Detect Wildcard Permissions
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    attr.name == "mode"
    regex.match(".*\\*.*", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard permission detected. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "Array"
    element := attr.value.value[_]
    element.ir_type == "String"
    regex.match(".*\\*.*", element.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard permission in array detected. (CWE-250)"
    }
}

# Rule 17: Detect Administrative Policies
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)administratoraccess", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Administrative policy detected. (CWE-250)"
    }
}

# Rule 18: Detect Execute Run Action
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "VariableReference"
    attr.name == "action"
    attr.value.value == ":run"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execute action running as root. (CWE-250)"
    }
}

# Rule 19: Detect Puppet Exec without user attribute (runs as root implicitly)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    node.type == "exec"
    attrs := glitch_lib.all_attributes(node)
    not user_attribute_exists(attrs)
    result := {
        "type": "sec_def_admin",
        "element": node,
        "path": parent.path,
        "description": "Puppet exec resource without user attribute (runs as root). (CWE-250)"
    }
}

# Helper to check if user attribute exists
user_attribute_exists(attrs) {
    attr := attrs[_]
    attr.name == "user"
}