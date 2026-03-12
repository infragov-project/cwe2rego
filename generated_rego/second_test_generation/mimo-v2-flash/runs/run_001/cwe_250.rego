package glitch

import data.glitch_lib

# Ansible IAM wildcard detection - Action
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    node.type == "community.aws.iam_policy"
    
    attrs := glitch_lib.all_attributes(node)
    policy_attr := attrs[_]
    policy_attr.name == "policy_json"
    
    policy_attr.value.ir_type == "String"
    regex.match("(?i)\"Action\"\\s*:\\s*\"[^\"]*\\*[^\"]*\"", policy_attr.value.value)
    
    result := {
        "type": "sec_def_admin",
        "element": policy_attr,
        "path": parent.path,
        "description": "Overly permissive IAM policy with wildcard actions (CWE-250)."
    }
}

# Ansible IAM wildcard detection - Resource
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    node.type == "community.aws.iam_policy"
    
    attrs := glitch_lib.all_attributes(node)
    policy_attr := attrs[_]
    policy_attr.name == "policy_json"
    
    policy_attr.value.ir_type == "String"
    regex.match("(?i)\"Resource\"\\s*:\\s*\"\\*\"", policy_attr.value.value)
    
    result := {
        "type": "sec_def_admin",
        "element": policy_attr,
        "path": parent.path,
        "description": "Overly permissive IAM policy with wildcard resources (CWE-250)."
    }
}

# Ansible Unnecessary Become detection (avoiding unsafe variable)
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    play_attrs := glitch_lib.all_attributes(parent)
    become_attr := play_attrs[_]
    become_attr.name == "become"
    become_attr.value.ir_type == "Boolean"
    become_attr.value.value == true
    
    result := {
        "type": "sec_def_admin",
        "element": become_attr,
        "path": parent.path,
        "description": "Unnecessary privilege escalation (become) for non-critical operations (CWE-250)."
    }
}

# Puppet Firewall Unrestricted Source detection for MySQL port
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    node.type == "firewall"
    
    attrs := glitch_lib.all_attributes(node)
    source_attr := attrs[_]
    source_attr.name == "source"
    source_attr.value.ir_type == "String"
    source_attr.value.value == "0.0.0.0/0"
    
    port_attr := attrs[_]
    port_attr.name == "dport"
    port_attr.value.ir_type == "String"
    port_attr.value.value == "3306"
    
    result := {
        "type": "sec_def_admin",
        "element": source_attr,
        "path": parent.path,
        "description": "Unrestricted network access to MySQL port 3306 (CWE-250)."
    }
}

# Puppet Firewall Unrestricted Source detection for RDP port
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    node.type == "firewall"
    
    attrs := glitch_lib.all_attributes(node)
    source_attr := attrs[_]
    source_attr.name == "source"
    source_attr.value.ir_type == "String"
    source_attr.value.value == "0.0.0.0/0"
    
    port_attr := attrs[_]
    port_attr.name == "dport"
    port_attr.value.ir_type == "String"
    port_attr.value.value == "3389"
    
    result := {
        "type": "sec_def_admin",
        "element": source_attr,
        "path": parent.path,
        "description": "Unrestricted network access to RDP port 3389 (CWE-250)."
    }
}

# Generic detection for unrestricted source in firewall rules
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    node.type == "firewall"
    
    attrs := glitch_lib.all_attributes(node)
    source_attr := attrs[_]
    source_attr.name == "source"
    source_attr.value.ir_type == "String"
    (source_attr.value.value == "0.0.0.0/0" or source_attr.value.value == "0.0.0.0" or source_attr.value.value == "any" or source_attr.value.value == "*")
    
    result := {
        "type": "sec_def_admin",
        "element": source_attr,
        "path": parent.path,
        "description": "Unrestricted network access detected (CWE-250)."
    }
}