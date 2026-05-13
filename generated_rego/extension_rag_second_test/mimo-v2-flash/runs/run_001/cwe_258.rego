package glitch

import data.glitch_lib

sensitive_keywords := {"password", "pwd", "pass", "secret", "credential"}

is_empty_password_value(v) {
    v.ir_type == "String"
    regex.match("^\\s*$", v.value)
} else {
    v.ir_type == "Null"
} else {
    v.ir_type == "Undef"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var := parent.variables[_]
    lower_name := lower(var.name)
    some keyword
    sensitive_keywords[keyword]
    regex.match(sprintf("(?i).*%s.*", [keyword]), lower_name)
    is_empty_password_value(var.value)
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - This can lead to unauthorized access. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr := parent.attributes[_]
    lower_name := lower(attr.name)
    some keyword
    sensitive_keywords[keyword]
    regex.match(sprintf("(?i).*%s.*", [keyword]), lower_name)
    is_empty_password_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - This can lead to unauthorized access. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    atomic_unit := parent.atomic_units[_]
    attr := atomic_unit.attributes[_]
    lower_name := lower(attr.name)
    some keyword
    sensitive_keywords[keyword]
    regex.match(sprintf("(?i).*%s.*", [keyword]), lower_name)
    is_empty_password_value(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - This can lead to unauthorized access. (CWE-258)"
    }
}