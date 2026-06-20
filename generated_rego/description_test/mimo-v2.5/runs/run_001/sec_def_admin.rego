package glitch

import data.glitch_lib

user_attr_names := {"User", "user", "remote_user", "runAsUser", "RemoteUser"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "Action"
    attr.value.ir_type == "String"
    attr.value.value == "*"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard permission in Action field - Grants administrative access to all API actions. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "Action"
    attr.value.ir_type == "Array"
    count(attr.value.value) > 0
    attr.value.value[_].value == "*"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard permission in Action field - Grants administrative access to all API actions. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "Resource"
    attr.value.ir_type == "String"
    attr.value.value == "*"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard permission in Resource field - Grants administrative access to all resources. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "Resource"
    attr.value.ir_type == "Array"
    count(attr.value.value) > 0
    attr.value.value[_].value == "*"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Wildcard permission in Resource field - Grants administrative access to all resources. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "privileged"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged container detected - Grants full host-level kernel access. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "Privileged"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged container detected - Grants full host-level kernel access. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "hostNetwork"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Host network namespace sharing detected - Increases the blast radius of container compromise. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "hostPID"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Host PID namespace sharing detected - Increases the blast radius of container compromise. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    user_attr_names[attr.name]
    attr.value.ir_type == "String"
    attr.value.value == "root"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Root user execution detected - Processes run with root privileges. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    user_attr_names[attr.name]
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Root user execution detected (UID 0) - Processes run with root privileges. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "acl"
    attr.value.ir_type == "String"
    regex.match("(?i)^public-read", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Publicly accessible storage detected - Grants anonymous or public access to storage. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "publicRead"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Publicly accessible storage detected - Grants anonymous or public access to storage. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "publiclyAccessible"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Publicly accessible resource detected - Data store or cache directly reachable from the internet. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "PolicyName"
    attr.value.ir_type == "String"
    regex.match("(?i)(AdministratorAccess|PowerUserAccess)", attr.value.value)
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Administrative policy attached - Grants near-total control over cloud resources. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "CidrIp"
    attr.value.ir_type == "String"
    attr.value.value == "0.0.0.0/0"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Administrative port open to internet - Management access exposed to public network. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "cidr_blocks"
    attr.value.ir_type == "Array"
    count(attr.value.value) > 0
    attr.value.value[_].ir_type == "String"
    attr.value.value[_].value == "0.0.0.0/0"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Administrative port open to internet - Management access exposed to public network. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "ipv6_cidr_blocks"
    attr.value.ir_type == "Array"
    count(attr.value.value) > 0
    attr.value.value[_].ir_type == "String"
    attr.value.value[_].value == "::/0"
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Administrative port open to internet via IPv6 - Management access exposed to public network. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "command"
    glitch_lib.traverse(attr.value, ".*root@.*")
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Root user login in command - Executing commands as root via SSH. (CWE-269)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "command"
    glitch_lib.traverse(attr.value, ".*StrictHostKeyChecking=no.*")
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "SSH host key checking disabled in command - Insecure SSH configuration. (CWE-269)"
    }
}