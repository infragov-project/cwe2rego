package glitch

import data.glitch_lib

privileged_user_attributes = {"user", "remote_user", "become_user"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)^root$", attr.value.value)
    some attr_name
    privileged_user_attributes[attr_name]
    attr.name == attr_name
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged execution context detected. User set to root without justification. (CWE-250)"
    }
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
    glitch_lib.traverse(attr.value, "root@")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Privileged execution context detected. Running as root user without justification. (CWE-250)"
    }
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
    glitch_lib.traverse(attr.value, "sudo")
    
    result := {
        "type": "sec_def_admin",
        "element": attr,
        "path": parent.path,
        "description": "Unnecessary sudo/elevation detected in command. May violate least privilege principle. (CWE-250)"
    }
}