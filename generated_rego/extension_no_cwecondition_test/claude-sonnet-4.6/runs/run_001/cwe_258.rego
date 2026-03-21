package glitch

import data.glitch_lib

is_password_name(name) {
    regex.match("(?i).*\\[['\"](password|passwd|pwd)['\"]\\]$", name)
}

is_password_name(name) {
    not regex.match("(?i).*\\[", name)
    regex.match("(?i).*(password|passwd|pwd)", name)
}

is_password_name(name) {
    not regex.match("(?i).*\\[", name)
    regex.match("(?i).*[a-z]key$", name)
    not regex.match("(?i).*_key$", name)
}

is_empty_or_null(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty_or_null(value) {
    value.ir_type == "Null"
}

is_empty_or_null(value) {
    value.ir_type == "Undef"
}

is_empty_str_node(parent, name) {
    walk(parent, [_, node])
    node.ir_type == "Attribute"
    node.value.ir_type == "String"
    node.value.value == ""
    name == node.name
}

is_empty_str_node(parent, name) {
    walk(parent, [_, node])
    node.ir_type == "Variable"
    node.value.ir_type == "String"
    node.value.value == ""
    name == node.name
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    vars := glitch_lib.all_variables(parent)
    var := vars[_]
    is_password_name(var.name)
    is_empty_or_null(var.value)
    result := {
        "type": "sec_empty_pass",
        "element": var,
        "path": parent.path,
        "description": "Empty password in configuration file - Using an empty string as a password is insecure. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_name(attr.name)
    is_empty_or_null(attr.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Using an empty string as a password is insecure. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    attrs := glitch_lib.all_attributes(parent)
    attr := attrs[_]
    is_password_name(attr.name)
    attr.value.ir_type == "FunctionCall"
    arg := attr.value.args[_]
    arg.ir_type == "VariableReference"
    is_empty_str_node(parent, arg.value)
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty password in configuration file - Using an empty string as a password is insecure. (CWE-258)"
    }
}