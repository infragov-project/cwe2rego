package glitch

import data.glitch_lib

privilege_attributes := {"become", "become_user", "become_flags", "runas", "sudo", "admin", "root", "privileged", "elevated", "administrator"}

check_privilege_value(value) {
    value.ir_type == "String"
    regex.match("(?i)^(root|admin|administrator|true|yes|privileged|elevated|sudo|admin)$", value.value)
} else {
    value.ir_type == "Boolean"
    value.value == true
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == privilege_attributes[_]
    check_privilege_value(attr.value)
    
    not necessity_justified(node)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - The operation requires or uses higher privilege levels than necessary. Follow the principle of least privilege. (CWE-250)"
    }
}

necessity_justified(node) {
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == "name"
    attr.value.ir_type == "String"
    
    restricted_operations := {"install", "configure", "setup", "manage", "service", "daemon", "system"}
    need_privilege := {v | v := restricted_operations[_]}
    
    count({op | op := need_privilege[_]; regex.match(sprintf("(?i).*%s.*", [op]), attr.value.value)}) > 0
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    unit_blocks := parent.unit_blocks[_]
    
    unit_blocks.name == "tasks"
    attrs := glitch_lib.all_attributes(unit_blocks)
    attr := attrs[_]
    
    attr.name == privilege_attributes[_]
    check_privilege_value(attr.value)
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Execution with Unnecessary Privileges - Global privilege escalation defined at block level may grant unnecessary privileges to all operations. Apply least privilege principle. (CWE-250)"
    }
}