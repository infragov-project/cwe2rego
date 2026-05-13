package glitch

import data.glitch_lib

is_empty_password(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty_password(value) {
    value.ir_type == "Null"
}

is_empty_password(value) {
    value.ir_type == "Undef"
}

is_password_field(name) {
    lower_name := lower(name)
    password_patterns := {"password", "pass", "passwd", "secret", "key", "token", "pwd"}
    count({x | lower_name == x; x := password_patterns[_]}) > 0
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    some i
    var := parent.variables[i]
    is_password_field(var.name)
    is_empty_password(var.value)
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_field(attr.name)
    is_empty_password(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Hash"
    some j
    item := node.value[j]
    item.key.ir_type == "String"
    is_password_field(item.key.value)
    is_empty_password(item.value)
    result := {
        "type": "sec_empty_pass",
        "element": item,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    node.ir_type == "Array"
    some j
    element := node.value[j]
    element.ir_type == "Hash"
    some k
    item := element.value[k]
    item.key.ir_type == "String"
    is_password_field(item.key.value)
    is_empty_password(item.value)
    result := {
        "type": "sec_empty_pass",
        "element": item,
        "path": parent.path,
        "description": "Empty password in configuration file - Password fields should not be empty. (CWE-258)"
    }
}