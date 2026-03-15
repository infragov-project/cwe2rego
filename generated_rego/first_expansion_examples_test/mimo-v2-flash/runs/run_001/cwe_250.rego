package glitch

import data.glitch_lib

privileged_users := {"root", "admin", "administrator", "sudo"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables in UnitBlock (e.g., Ansible vars)
    variable := parent.variables[_]
    regex.match("(?i).*user.*", variable.name)
    variable.value.ir_type == "String"
    lower_value := lower(variable.value.value)
    lower_value == "root"
    
    result := {
        "type": "sec_def_admin",
        "element": variable,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in UnitBlock (e.g., Ansible playbook attributes)
    attribute := parent.attributes[_]
    regex.match("(?i).*user.*", attribute.name)
    attribute.value.ir_type == "String"
    lower_value := lower(attribute.value.value)
    lower_value == "root"
    
    result := {
        "type": "sec_def_admin",
        "element": attribute,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check attributes in AtomicUnit (e.g., Chef resources)
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    regex.match("(?i).*user.*", attr.name)
    attr.value.ir_type == "String"
    lower_value := lower(attr.value.value)
    lower_value == "root"
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - (CWE-250)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for become_user patterns in Ansible
    attribute := parent.attributes[_]
    attribute.name == "become_user"
    attribute.value.ir_type == "String"
    lower_value := lower(attribute.value.value)
    lower_value == "root"
    
    result := {
        "type": "sec_def_admin",
        "element": attribute,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - (CWE-250)"
    }
}