package glitch

import data.glitch_lib

password_attrs := {"password", "pwd", "admin_password", "master_password", "secret"}

is_empty_password(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    attr.name == password_attrs[_]
    is_empty_password(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Authentication mechanisms should not use empty passwords. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    var.name == password_attrs[_]
    is_empty_password(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in variable definition - Variables used for passwords should not be empty. (CWE-258)"
    }
}