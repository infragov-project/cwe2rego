package glitch

import data.glitch_lib

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    value := attr.value
    
    value.ir_type == "String"
    value.value in {"0.0.0.0", "::/0"}
    
    glitch_lib.contains(attr.name, "bind") ||
    glitch_lib.contains(attr.name, "ip") ||
    glitch_lib.contains(attr.name, "address") ||
    glitch_lib.contains(attr.name, "network")
    
    result := {
        "type": "sec_invalid_bind",
        "element": attr,
        "path": parent.path,
        "description": "Unrestricted bind address - Service bound to 0.0.0.0 or ::/0. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    value := var.value
    
    value.ir_type == "String"
    value.value in {"0.0.0.0", "::/0"}
    
    glitch_lib.contains(var.name, "bind") ||
    glitch_lib.contains(var.name, "ip") ||
    glitch_lib.contains(var.name, "address") ||
    glitch_lib.contains(var.name, "network")
    
    result := {
        "type": "sec_invalid_bind",
        "element": var,
        "path": parent.path,
        "description": "Unrestricted bind address - Variable set to 0.0.0.0 or ::/0. (CWE-284)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, n])
    n.ir_type == "String"
    n.value in {"0.0.0.0", "::/0"}
    
    path_str := concat(".", path)
    glitch_lib.contains(path_str, "bind") ||
    glitch_lib.contains(path_str, "ip") ||
    glitch_lib.contains(path_str, "address") ||
    glitch_lib.contains(path_str, "network")
    
    result := {
        "type": "sec_invalid_bind",
        "element": n,
        "path": parent.path,
        "description": "Unrestricted bind address - Configuration value set to 0.0.0.0 or ::/0. (CWE-284)"
    }
}