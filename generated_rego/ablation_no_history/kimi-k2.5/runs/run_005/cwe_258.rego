package glitch

import data.glitch_lib

password_keywords := {"password", "pwd", "passwd"}
secret_keywords := {"secret", "token", "key"}

is_empty_string(value) {
    value.ir_type == "String"
    value.value == ""
}

is_null(value) {
    value.ir_type == "Null"
}

is_undef(value) {
    value.ir_type == "Undef"
}

is_empty_or_null(value) {
    is_empty_string(value)
}

is_empty_or_null(value) {
    is_null(value)
}

is_empty_or_null(value) {
    is_undef(value)
}

contains_password_keyword(name) {
    lower_name := lower(name)
    kw := password_keywords[_]
    regex.match(sprintf(".*(^|_|\\b)%s($|\\b|_).*", [kw]), lower_name)
}

contains_secret_keyword_with_context(name) {
    lower_name := lower(name)
    some kw in secret_keywords
    regex.match(sprintf(".*(^|_)(%s)($|_).*", [kw]), lower_name)
    regex.match(".*(password|pass|auth|credential|access).*", lower_name)
}

is_password_field_name(name) {
    contains_password_keyword(name)
}

is_password_field_name(name) {
    contains_secret_keyword_with_context(name)
}

is_password_field_name(name) {
    lower_name := lower(name)
    regex.match(".*(^|_)(auth|bind|admin)_?password($|_).*", lower_name)
}

is_password_field_name(name) {
    lower_name := lower(name)
    regex.match("^password_?(hash|key)?$", lower_name)
}

is_passthrough_function(name) {
    lower_name := lower(name)
    lower_name == "mysql_password"
} else {
    lower_name := lower(name)
    lower_name == "password_hash"
} else {
    lower_name := lower(name)
    lower_name == "md5"
} else {
    lower_name := lower(name)
    lower_name == "sha1"
} else {
    lower_name := lower(name)
    lower_name == "sha256"
} else {
    lower_name := lower(name)
    regex.match(".*_password$", lower_name)
}

is_secure_empty_usage(attr_name, value) {
    value.ir_type == "FunctionCall"
    is_passthrough_function(value.name)
    count(value.args) > 0
    arg := value.args[0]
    arg.ir_type == "VariableReference"
} else {
    value.ir_type == "FunctionCall"
    is_passthrough_function(value.name)
    count(value.args) > 0
    arg := value.args[0]
    arg.ir_type == "String"
    arg.value != ""
}

check_empty_or_null_in_expression(expr) {
    is_empty_or_null(expr)
}

check_empty_or_null_in_expression(expr) {
    expr.ir_type == "FunctionCall"
    some arg in expr.args
    is_empty_or_null(arg)
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    is_password_field_name(v.name)
    check_empty_or_null_in_expression(v.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": v,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password attributes should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    atomic_units := glitch_lib.all_atomic_units(parent)
    node := atomic_units[_]
    
    attrs := glitch_lib.all_attributes(node)
    attr := attrs[_]
    is_password_field_name(attr.name)
    check_empty_or_null_in_expression(attr.value)
    not is_secure_empty_usage(attr.name, attr.value)
    
    result := {
        "type": "sec_empty_pass",
        "element": attr,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password attributes should not be empty or null. (CWE-258)"
    }
}

Glitch_Analysis[result] {
    parent := glitch_lib._gather_parent_unit_blocks[_]
    parent.path != ""
    
    walk(parent, [path, node])
    node.ir_type == "Attribute"
    is_password_field_name(node.name)
    check_empty_or_null_in_expression(node.value)
    not is_secure_empty_usage(node.name, node.value)
    
    not node_in_variable_or_atomic_unit(parent, node)
    
    result := {
        "type": "sec_empty_pass",
        "element": node,
        "path": parent.path,
        "description": "Empty Password in Configuration File - Password attributes should not be empty or null. (CWE-258)"
    }
}

node_in_variable_or_atomic_unit(parent, attr) {
    vars := glitch_lib.all_variables(parent)
    v := vars[_]
    v.name == attr.name
    v.line == attr.line
} else {
    some unit in glitch_lib.all_atomic_units(parent)
    some a in glitch_lib.all_attributes(unit)
    a.name == attr.name
    a.line == attr.line
}