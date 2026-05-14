package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    lower_name := lower(attr.name)
    privilege_keywords := {"user", "remote_user", "runas", "owner", "privileged", "capabilities", "runasuser", "runasroot"}
    
    lower_name == privilege_keywords[_]

    value_check := attr.value
    value_check.ir_type == "String"
    lower_val := lower(value_check.value)
    
    lower_val == "root"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privilege Escalation Pathways - Configuration allows privilege escalation or excessive runtime privileges. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    lower_name := lower(attr.name)
    permission_keywords := {"action", "resource", "permissions", "capability", "cap"}
    
    lower_name == permission_keywords[_]

    attr.value.ir_type == "String"
    attr.value.value == "*"

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Overly Permissive Identity Roles - Policy grants wildcard (*) permissions. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]

    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]

    lower_name := lower(attr.name)
    network_keywords := {"cidr", "ip_range", "network", "source", "ip"}
    
    lower_name == network_keywords[_]

    attr.value.ir_type == "String"
    regex.match("0\\.0\\.0\\.0/0", attr.value.value)

    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive Network Permissions - Unrestricted inbound access to privileged services. (CWE-250)"
    }
}