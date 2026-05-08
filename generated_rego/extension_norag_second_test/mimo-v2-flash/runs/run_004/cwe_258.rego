package glitch

import data.glitch_lib

password_keywords := {"password", "pwd", "pass", "secret", "credential", "token", "auth"}

is_password_name(name) {
    lower_name := lower(name)
    some keyword
    password_keywords[keyword]
    contains(lower_name, keyword)
}

is_empty_password_value(value) {
    value.ir_type == "String"
    value.value == ""
}

is_empty_password_value(value) {
    value.ir_type == "Null"
}

is_empty_password_value(value) {
    value.ir_type == "Undef"
}

is_placeholder_password_value(value) {
    value.ir_type == "String"
    placeholder_patterns := {"todo", "change_me", "placeholder", "<empty>", "false"}
    lower_value := lower(value.value)
    some pattern
    placeholder_patterns[pattern]
    lower_value == pattern
}

is_password_violation(node) {
    node.ir_type == "Variable"
    is_password_name(node.name)
    is_empty_password_value(node.value)
}

is_password_violation(node) {
    node.ir_type == "Variable"
    is_password_name(node.name)
    is_placeholder_password_value(node.value)
}

is_password_violation(node) {
    node.ir_type == "Attribute"
    is_password_name(node.name)
    is_empty_password_value(node.value)
}

is_password_violation(node) {
    node.ir_type == "Attribute"
    is_password_name(node.name)
    is_placeholder_password_value(node.value)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    walk(parent, [path, node])
    is_password_violation(node)
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty or placeholder password detected - Passwords should not be empty or placeholder values to prevent unauthorized access. (CWE-258)"
    }
}