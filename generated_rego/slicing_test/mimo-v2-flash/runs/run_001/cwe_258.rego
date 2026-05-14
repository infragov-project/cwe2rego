package glitch

import data.glitch_lib

password_keywords := {"password", "pwd", "pass", "secret", "token", "credential", "key", "auth"}

connection_string_keywords := {"connectionstring", "database_url", "dsn", "connection_string"}

check_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

check_connection_string_empty_password(value) {
    value.ir_type == "String"
    regex.match("(?i)(pwd|password|pass)=(&|;|$)", value.value)
}

contains_password_keyword(name) {
    name.ir_type == "String"
    regex.match("(?i).*(password|pwd|pass|secret|token|credential|key|auth).*", name.value)
}

contains_connection_string_keyword(name) {
    name.ir_type == "String"
    regex.match("(?i).*(connectionstring|database_url|dsn|connection_string).*", name.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables in UnitBlock for empty password fields
    var := parent.variables[_]
    var.ir_type == "Variable"
    contains_password_keyword({"ir_type": "String", "value": var.name})
    check_empty_value(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - Password field is set to an empty string, null, or undef, allowing unauthorized access. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check variables for connection strings with empty password
    var := parent.variables[_]
    var.ir_type == "Variable"
    contains_connection_string_keyword({"ir_type": "String", "value": var.name})
    var.value.ir_type == "String"
    check_connection_string_empty_password(var.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in connection string - Connection string contains empty password parameter, allowing unauthorized access. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in atomic units for empty password fields
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    contains_password_keyword(attr.name)
    check_empty_value(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password field is set to an empty string, null, or undef, allowing unauthorized access. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes for connection strings with empty password in atomic units
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    contains_connection_string_keyword(attr.name)
    attr.value.ir_type == "String"
    check_connection_string_empty_password(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in connection string - Connection string contains empty password parameter, allowing unauthorized access. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in unit blocks for empty password fields (e.g., Puppet class parameters)
    ub := parent.unit_blocks[_]
    attrs := glitch_lib.all_attributes(ub)
    attr := attrs[_]
    
    contains_password_keyword(attr.name)
    check_empty_value(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in class definition - Password field is set to an empty string, null, or undef, allowing unauthorized access. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check attributes in unit blocks for connection strings with empty password
    ub := parent.unit_blocks[_]
    attrs := glitch_lib.all_attributes(ub)
    attr := attrs[_]
    
    contains_connection_string_keyword(attr.name)
    attr.value.ir_type == "String"
    check_connection_string_empty_password(attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in connection string - Connection string contains empty password parameter, allowing unauthorized access. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    # Check for connection strings in String values regardless of field name
    # This handles cases where connection strings might be in generic fields
    all_strings := {n |
        walk(parent, [path, n])
        n.ir_type == "String"
    }
    str := all_strings[_]
    check_connection_string_empty_password(str)
    
    result := {
        "type": "sec_empty_pass",
        "element": str,
        "path": parent.path,
        "description": "Empty password in connection string - Connection string contains empty password parameter, allowing unauthorized access. (CWE-258)"
    }
}