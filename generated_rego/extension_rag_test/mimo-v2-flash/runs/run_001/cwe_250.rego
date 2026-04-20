package glitch

import data.glitch_lib

# Detect remote_user set to root in Ansible
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    parent.type == "script"
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.name == "remote_user"
    attr.value.ir_type == "String"
    contains(lower(attr.value.value), "root")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Running as root user. (CWE-250)"
    }
}

# Detect user attribute set to root in Chef resources
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "user"
    attr.value.ir_type == "String"
    contains(lower(attr.value.value), "root")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Running as root user. (CWE-250)"
    }
}

# General detection for user attribute set to root
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "user"
    attr.value.ir_type == "String"
    contains(lower(attr.value.value), "root")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Running as root user. (CWE-250)"
    }
}

# Detect remote_user attribute set to root
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "remote_user"
    attr.value.ir_type == "String"
    contains(lower(attr.value.value), "root")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Running as root user. (CWE-250)"
    }
}

# Detect owner attribute set to root
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "owner"
    attr.value.ir_type == "String"
    contains(lower(attr.value.value), "root")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Running as root user. (CWE-250)"
    }
}

# Detect run_as_user attribute set to root
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "run_as_user"
    attr.value.ir_type == "String"
    contains(lower(attr.value.value), "root")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Running as root user. (CWE-250)"
    }
}

# Detect username attribute set to root
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.name == "username"
    attr.value.ir_type == "String"
    contains(lower(attr.value.value), "root")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with unnecessary privileges - Running as root user. (CWE-250)"
    }
}

# Detect container running as root (common in Kubernetes/container IaC) - Integer case
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    contains(lower(node.type), "container")
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "runAsUser"
    attr.value.ir_type == "Integer"
    attr.value.value == 0
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container running as root user - Unnecessary privileges granted. (CWE-250)"
    }
}

# Detect container running as root (common in Kubernetes/container IaC) - String case
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    contains(lower(node.type), "container")
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "runAsUser"
    attr.value.ir_type == "String"
    (attr.value.value == "0" | contains(lower(attr.value.value), "root"))
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Container running as root user - Unnecessary privileges granted. (CWE-250)"
    }
}

# Detect privileged container execution
Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    contains(lower(node.type), "container")
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "privileged"
    attr.value.ir_type == "Boolean"
    attr.value.value == true
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged container detected - Excessive execution context privileges. (CWE-250)"
    }
}