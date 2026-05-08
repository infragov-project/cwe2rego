package glitch

import data.glitch_lib

password_keywords := {"password", "pwd", "pass", "secret", "credential", "auth_token", "activationkey", "key", "token"}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    some keyword
    password_keywords[keyword]
    regex.match(sprintf("(?i).*%s.*", [keyword]), var.name)
    
    var.value.ir_type == "String"
    var.value.value == ""
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": sprintf("Empty password assigned to password field '%s'. (CWE-258)", [var.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    some keyword
    password_keywords[keyword]
    regex.match(sprintf("(?i).*%s.*", [keyword]), var.name)
    
    var.value.ir_type == "Null"
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": sprintf("Null password assigned to password field '%s'. (CWE-258)", [var.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    variables := glitch_lib.all_variables(parent)
    var := variables[_]
    
    some keyword
    password_keywords[keyword]
    regex.match(sprintf("(?i).*%s.*", [keyword]), var.name)
    
    var.value.ir_type == "Undef"
    
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": sprintf("Undefined password assigned to password field '%s'. (CWE-258)", [var.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    some keyword
    password_keywords[keyword]
    regex.match(sprintf("(?i).*%s.*", [keyword]), attr.name)
    
    attr.value.ir_type == "String"
    attr.value.value == ""
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Empty password assigned to password field '%s'. (CWE-258)", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    some keyword
    password_keywords[keyword]
    regex.match(sprintf("(?i).*%s.*", [keyword]), attr.name)
    
    attr.value.ir_type == "Null"
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Null password assigned to password field '%s'. (CWE-258)", [attr.name])
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    
    some keyword
    password_keywords[keyword]
    regex.match(sprintf("(?i).*%s.*", [keyword]), attr.name)
    
    attr.value.ir_type == "Undef"
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": sprintf("Undefined password assigned to password field '%s'. (CWE-258)", [attr.name])
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
    regex.match("(?i).*(password|pwd|pass)=;", attr.value.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password parameter in connection string. (CWE-258)"
    }
}