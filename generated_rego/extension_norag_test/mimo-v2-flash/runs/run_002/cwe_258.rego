package glitch

import data.glitch_lib

password_keywords = {"password", "passwd", "pwd", "secret", "token", "key", "credential", "auth"}

is_password_related(name) {
    lower_name := lower(name)
    some keyword
    password_keywords[keyword]
    contains(lower_name, keyword)
}

is_empty_value(value) {
    value.ir_type == "String"
    regex.match("^\\s*$", value.value)
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check top-level variables in the UnitBlock
    some var in parent.variables
    is_password_related(var.name)
    is_empty_value(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in variable - Variable assigned empty password value. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check attributes in atomic units
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_password_related(attr.name)
    is_empty_value(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password attribute set to empty value. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    # Check variables in atomic units
    vars := glitch_lib.all_variables(node)
    var := vars[_]
    is_password_related(var.name)
    is_empty_value(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in variable - Variable assigned empty password value. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    attr.value.ir_type == "String"
    regex.match("(?i)(pwd|password)\\s*=\\s*;", attr.value.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Connection string with empty password - Empty password in connection string. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    vars := glitch_lib.all_variables(node)
    var := vars[_]
    var.value.ir_type == "String"
    regex.match("(?i)(pwd|password)\\s*=\\s*;", var.value.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Connection string with empty password - Empty password in connection string. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check top-level variables for connection strings
    some var in parent.variables
    var.value.ir_type == "String"
    regex.match("(?i)(pwd|password)\\s*=\\s*;", var.value.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Connection string with empty password - Empty password in connection string. (CWE-258)"
    }
}