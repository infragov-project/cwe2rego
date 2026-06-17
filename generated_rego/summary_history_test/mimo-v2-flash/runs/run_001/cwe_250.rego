package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in any node (UnitBlock or AtomicUnit)
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check for user attributes in Chef or other IaC technologies
    attr.name == "user"
    attr.value.ir_type == "String"
    glitch_lib.traverse(attr, "(?i)^root$")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Running as root user - Avoid running as root when not necessary. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in any node (UnitBlock or AtomicUnit)
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check for remote_user attributes in Ansible
    attr.name == "remote_user"
    attr.value.ir_type == "String"
    glitch_lib.traverse(attr, "(?i)^root$")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Running as root user - Avoid running as root when not necessary. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in any node (UnitBlock or AtomicUnit)
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    
    # Check for root@ patterns in command strings (Puppet and others)
    # Removed ir_type check to handle complex values like Sum
    glitch_lib.traverse(attr, "(?i)root@")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Running as root user - Avoid running as root when not necessary. (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "Action"
    attr.value.ir_type == "String"
    glitch_lib.traverse(attr, "^\\*$")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Over-permissive IAM policy with wildcard permissions (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "Resource"
    attr.value.ir_type == "String"
    glitch_lib.traverse(attr, "^\\*$")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Over-permissive IAM policy with wildcard permissions (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "Principal"
    attr.value.ir_type == "String"
    glitch_lib.traverse(attr, "^\\*$")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Over-permissive IAM policy with wildcard permissions (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "ClusterRole"
    attr.value.ir_type == "String"
    glitch_lib.traverse(attr, "(?i)cluster-admin|administrator|root|full-access")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Excessive role binding with high-privilege cluster role (CWE-250)"
    }
}

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
        "description": "Workload running with unnecessary privileges (root/privileged) (CWE-250)"
    }
}

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
        "description": "Workload running with unnecessary privileges (root/privileged) (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "allowPrivilegeEscalation"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Workload running with unnecessary privileges (root/privileged) (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "superuser"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Database privilege escalation with excessive permissions (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "superuser"
    attr.value.ir_type == "String"
    glitch_lib.traverse(attr, "(?i)ALL PRIVILEGES|superuser|admin")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Database privilege escalation with excessive permissions (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "admin"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Database privilege escalation with excessive permissions (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "admin"
    attr.value.ir_type == "String"
    glitch_lib.traverse(attr, "(?i)ALL PRIVILEGES|superuser|admin")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Database privilege escalation with excessive permissions (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "privileges"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Database privilege escalation with excessive permissions (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "privileges"
    attr.value.ir_type == "String"
    glitch_lib.traverse(attr, "(?i)ALL PRIVILEGES|superuser|admin")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Database privilege escalation with excessive permissions (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "ManagedPolicyArns"
    attr.value.ir_type == "String"
    glitch_lib.traverse(attr, "(?i)AdministratorAccess|full-access|root")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Serverless function with high-privilege execution role (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "Action"
    attr.value.ir_type == "String"
    glitch_lib.traverse(attr, "(?i)sts:AssumeRole|iam:PassRole")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted privilege escalation path (AssumeRole/PassRole) (CWE-250)"
    }
}