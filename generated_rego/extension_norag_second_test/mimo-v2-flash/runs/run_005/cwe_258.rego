package glitch

import data.glitch_lib

password_keywords := {"password", "secret", "passwd", "pwd"}

contains_password_keyword(name) {
    some keyword
    password_keywords[keyword]
    regex.match(sprintf("(?i).*%s.*", [keyword]), name)
}

is_empty_value(value) {
    value.ir_type == "String"
    value.value == ""
} else {
    value.ir_type == "Null"
} else {
    value.ir_type == "Undef"
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    var_node := glitch_lib.all_variables(parent)[_]
    contains_password_keyword(var_node.name)
    is_empty_value(var_node.value)
    result := {
        "type": "sec_empty_pass",
        "element": var_node,
        "path": parent.path,
        "description": "Use of empty string as password in variable - Weakness in setting passwords to empty values. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attr_node := glitch_lib.all_attributes(parent)[_]
    contains_password_keyword(attr_node.name)
    is_empty_value(attr_node.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr_node,
        "path": parent.path,
        "description": "Use of empty string as password in attribute - Weakness in setting passwords to empty values. (CWE-258)"
    }
}